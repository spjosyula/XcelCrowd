import { BaseService } from '../BaseService';
import { Types, ClientSession } from 'mongoose';
import { AIEvaluation, Solution } from '../../models';
import {
  IAIEvaluation,
  ISolution,
  SolutionStatus,
  EvaluationDecision 
} from '../../models/interfaces';
import { ApiError } from '../../utils/api.error';
import { logger } from '../../utils/logger';
import { HTTP_STATUS } from '../../constants';
import { MongoSanitizer } from '../../utils/mongo.sanitize';
import { v4 as uuidv4 } from 'uuid';
import { EvaluationPipelineController, evaluationPipelineController } from './EvaluationPipelineController';
import { scheduler, Scheduler } from '../../utils/scheduler';

// Configuration interface
interface IConfig {
  evaluation?: {
    maxRetryCount?: number;
    standardDurationMs?: number;
    architectReviewThreshold?: number;
  }
}

// Default configuration
const config: IConfig = {
  evaluation: {
    maxRetryCount: 3,
    standardDurationMs: 5 * 60 * 1000, // 5 minutes
    architectReviewThreshold: 70
  }
};

// Evaluation status type
type EvaluationStatus = 'pending' | 'in_progress' | 'completed' | 'failed';

// Interfaces for evaluation analytics and status
interface IEvaluationStatus {
  status: EvaluationStatus;
  progress: number;
  startedAt: Date | null;
  completedAt: Date | null;
  currentStage: string | null;
  estimatedCompletionTime: Date | null;
}

interface IEvaluationStage {
  name: string;
  field: keyof Pick<IAIEvaluation, 'spamFiltering' | 'requirementsCompliance' | 'codeQuality' | 'scoringFeedback'>;
  weight: number;
}

interface IEvaluationRetryOptions {
  forceRestart?: boolean;
  priority?: string;
  skipSteps?: string[];
}

interface IEvaluationAnalyticsOptions {
  startDate?: Date;
  endDate?: Date;
  challengeId?: string;
  groupBy?: 'day' | 'week' | 'month';
  limit?: number;
}

interface IEvaluationAnalyticsResult {
  summary: {
    total: number;
    byStatus: Record<string, number>;
  };
  timeAnalytics: any[];
  performance: {
    avgTime: number;
    minTime: number;
    maxTime: number;
    count: number;
  };
}

type PipelineResult = ReturnType<EvaluationPipelineController['executePipeline']> extends Promise<infer T> ? T : never;

/**
 * Service for orchestrating the AI evaluation pipeline
 * Manages the sequential workflow and state transitions for GitHub repository submissions
 */
export class AIEvaluationService extends BaseService {
  
  private readonly pipelineController: EvaluationPipelineController;

  // Maximum number of retries for evaluation 
  private readonly MAX_RETRY_COUNT: number;
  
  // Standard evaluation duration in milliseconds (for estimation)
  private readonly STANDARD_EVALUATION_DURATION_MS: number;
  

  /**
   * Constructor
   */
  constructor() {
    super();
    this.pipelineController = evaluationPipelineController;
    
    // Get configuration values with defaults
    this.MAX_RETRY_COUNT = config.evaluation?.maxRetryCount || 3;
    this.STANDARD_EVALUATION_DURATION_MS = config.evaluation?.standardDurationMs || 5 * 60 * 1000;

    // Register for scheduler events
    this.registerEventListeners();
  }

  /**
   * Register for scheduler events to process evaluations when challenge deadlines are reached
   */
  private registerEventListeners(): void {
    scheduler.on(Scheduler.EVENTS.CHALLENGE_DEADLINE_REACHED, async (challengeId: string) => {
      try {
        logger.info(`AI Evaluation service received challenge deadline event for ${challengeId}`);
        
        // Process the evaluations for this challenge
        await this.processEvaluationsForChallenge(challengeId);
        
        logger.info(`Completed processing AI evaluations for challenge ${challengeId} via event handler`);
      } catch (error) {
        logger.error(`Error processing AI evaluations for challenge ${challengeId} from event`, {
          challengeId,
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        });
      }
    });
  }

  /**
   * Start the AI evaluation process for a solution
   * @param solutionId - The ID of the solution to evaluate
   * @returns The created evaluation record
   */
  public async startEvaluation(solutionId: string): Promise<IAIEvaluation> {
    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }
    
    const sanitizedSolutionId = MongoSanitizer.sanitizeObjectId(solutionId);
    const traceId = uuidv4();

    try {
      return await this.withTransaction(async (session) => {
        // Check if solution exists
        const solution = await Solution.findById(sanitizedSolutionId).session(session);
        if (!solution) {
          logger.warn(`Solution not found for evaluation`, {
            solutionId: sanitizedSolutionId,
            traceId
          });
          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            'Solution not found',
            true,
            'SOLUTION_NOT_FOUND'
          );
        }

        // Check if solution is in evaluable state
        if (solution.status !== SolutionStatus.SUBMITTED) {
          logger.warn(`Solution is not in submittable state for AI evaluation`, {
            solutionId: sanitizedSolutionId,
            status: solution.status,
            traceId
          });
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Solution cannot be evaluated when in '${solution.status}' status`,
            true,
            'INVALID_SOLUTION_STATUS'
          );
        }

        // Validate GitHub repository URL
        const sanitizedGitHubUrl = MongoSanitizer.sanitizeGitHubUrl(solution.submissionUrl);
        if (!sanitizedGitHubUrl) {
          logger.warn(`Invalid GitHub repository URL`, {
            solutionId: sanitizedSolutionId,
            submissionUrl: solution.submissionUrl,
            traceId
          });
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Solution must have a valid GitHub repository URL',
            true,
            'INVALID_GITHUB_URL'
          );
        }
        
        // Check if evaluation already exists
        const existingEvaluation = await AIEvaluation.findOne({
          solution: sanitizedSolutionId
        }).session(session);

        if (existingEvaluation) {
          // If evaluation exists but failed, we can restart it if under max retry count
          if (existingEvaluation.status === 'failed' && 
              (!existingEvaluation.retryCount || existingEvaluation.retryCount < this.MAX_RETRY_COUNT)) {
            
            logger.info(`Restarting failed evaluation`, {
              solutionId: sanitizedSolutionId,
              evaluationId: existingEvaluation._id?.toString(),
              retryCount: existingEvaluation.retryCount || 0,
              traceId
            });
            
            // Increment retry count
            existingEvaluation.retryCount = (existingEvaluation.retryCount || 0) + 1;
            existingEvaluation.status = 'pending';
            existingEvaluation.failureReason = undefined;
            existingEvaluation.completedAt = undefined;
            
            // Clear previous results if we're retrying to ensure a fresh evaluation
            existingEvaluation.spamFiltering = undefined;
            existingEvaluation.requirementsCompliance = undefined;
            existingEvaluation.codeQuality = undefined;
            existingEvaluation.scoringFeedback = undefined;
            
            // Store retry metadata
            existingEvaluation.metadata = {
              ...(existingEvaluation.metadata || {}),
              lastRetryAt: new Date(),
              traceId
            };
            
            await existingEvaluation.save({ session });
            
            // Schedule the evaluation and await its start (not full completion)
            await this.scheduleEvaluationProcessing(existingEvaluation._id?.toString(), traceId);
            
            return existingEvaluation;
          }
          
          // If max retries reached, don't retry again
          if (existingEvaluation.status === 'failed' && 
              existingEvaluation.retryCount && 
              existingEvaluation.retryCount >= this.MAX_RETRY_COUNT) {
            
            logger.warn(`Maximum retry count reached for evaluation`, {
              solutionId: sanitizedSolutionId,
              evaluationId: existingEvaluation._id?.toString(),
              retryCount: existingEvaluation.retryCount,
              traceId
            });
            
            throw new ApiError(
              HTTP_STATUS.TOO_MANY_REQUESTS,
              'Maximum retry attempts reached for this evaluation',
              true,
              'MAX_RETRY_REACHED'
            );
          }
          
          // Otherwise, return the existing evaluation (in progress or completed)
          logger.info(`Evaluation already exists for solution`, {
            solutionId: sanitizedSolutionId,
            evaluationId: existingEvaluation._id?.toString(),
            status: existingEvaluation.status,
            traceId
          });
          
          return existingEvaluation;
        }
        
        // Create new evaluation record
        const evaluation = new AIEvaluation({
          solution: sanitizedSolutionId,
          status: 'pending',
          retryCount: 0,
          metadata: {
            createdVia: 'api',
            traceId
          }
        });
        
        await evaluation.save({ session });
        
        logger.info(`Created new AI evaluation`, {
          solutionId: sanitizedSolutionId,
          evaluationId: evaluation._id?.toString(),
          traceId
        });
        
        // Schedule the evaluation and await its start (not full completion)
        await this.scheduleEvaluationProcessing(evaluation._id?.toString(), traceId);
        
        return evaluation;
      });
    } catch (error) {
      logger.error(`Error starting evaluation`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        traceId
      });
      
      if (error instanceof ApiError) throw error;
      
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to start evaluation',
        true,
        'EVALUATION_START_ERROR'
      );
    }
  }

  /**
   * Schedule an evaluation for processing
   * Returns a promise that resolves once the evaluation has been marked as in_progress
   * @param evaluationId - The ID of the evaluation to process
   * @param traceId - Trace ID for logging
   */
  private async scheduleEvaluationProcessing(evaluationId: string | undefined, traceId: string): Promise<void> {
    if (!evaluationId) {
      logger.error('Missing evaluation ID for processing', { traceId });
      return;
    }

    // Start processing in the background but return a promise that resolves
    // once the evaluation is confirmed to be in_progress status
    return new Promise<void>((resolve, reject) => {
      // Run process in the background
      setImmediate(async () => {
        try {
          // First mark as in_progress so we have clear state transition
          await this.updateEvaluationStatus(evaluationId, 'in_progress', traceId);
          
          // Signal that we've started processing
          resolve();
          
          // Then start the actual processing
          await this.processEvaluationSequence(evaluationId, traceId);
        } catch (error) {
          logger.error(`Error processing evaluation`, {
            evaluationId,
            error: error instanceof Error ? error.message : String(error),
            traceId
          });
          
          // Only reject if we haven't resolved yet (meaning the status update failed)
          // Otherwise the error is handled within processEvaluationSequence
          reject(error);
        }
      });
    });
  }

  /**
   * Update the status of an evaluation
   * @param evaluationId - The ID of the evaluation
   * @param status - The new status
   * @param traceId - Trace ID for logging
   */
  private async updateEvaluationStatus(
    evaluationId: string, 
    status: EvaluationStatus, 
    traceId: string, 
    additionalData: Record<string, any> = {}
  ): Promise<void> {
    await this.withTransaction(async (session) => {
      const evaluation = await AIEvaluation.findById(evaluationId).session(session);
      
      if (!evaluation) {
        logger.warn(`Evaluation not found for status update`, { 
          evaluationId,
          status,
          traceId 
        });
        return;
      }
      
      evaluation.status = status;
      
      // Update metadata
      evaluation.metadata = {
        ...(evaluation.metadata || {}),
        [`${status}At`]: new Date(),
        traceId,
        ...additionalData
      };
      
      // Update specific fields for status changes
      if (status === 'in_progress') {
        evaluation.metadata.processingStartedAt = new Date();
      } else if (status === 'completed') {
        evaluation.completedAt = new Date();
      } else if (status === 'failed' && additionalData.failureReason) {
        evaluation.failureReason = additionalData.failureReason;
      }
      
      await evaluation.save({ session });
      
      logger.info(`Updated evaluation status to ${status}`, {
        evaluationId,
        traceId
      });
    });
  }

  /**
   * Process the evaluation sequence for a solution
   * @param evaluationId - The ID of the evaluation to process
   * @param traceId - Trace ID for logging
   */
  private async processEvaluationSequence(evaluationId: string, traceId: string): Promise<void> {
    try {
      // Find the evaluation
      const evaluation = await AIEvaluation.findById(evaluationId);
      
      if (!evaluation) {
        logger.error(`Evaluation not found for processing`, {
          evaluationId,
          traceId
        });
        return;
      }
      
      // Update status to in_progress
      await this.updateEvaluationStatus(evaluationId, 'in_progress', traceId);
      
      // Get the solution for evaluation
      const solution = await Solution.findById(evaluation.solution)
        .populate('challenge', 'title description requirements deadline status');
      
      if (!solution) {
        logger.error(`Solution not found for evaluation`, {
          evaluationId,
          solutionId: evaluation.solution.toString(),
          traceId
        });
        
        await this.updateEvaluationStatus(evaluationId, 'failed', traceId, {
          failureReason: 'Solution not found'
        });
        
        return;
      }
      
      // Check solution deadline before processing
      const challenge = solution.challenge;
      // Check if challenge is populated (is an object, not just an ID)
      if (challenge && typeof challenge === 'object' && 'deadline' in challenge) {
        const now = new Date();
        const deadline = new Date(challenge.deadline as Date);
        
        // Only evaluate solutions after the deadline has passed
        // This ensures all solutions are processed together and
        // students can't resubmit after seeing AI feedback
        if (now < deadline) {
          logger.warn(`Challenge deadline has not passed yet, skipping evaluation`, {
            evaluationId,
            solutionId: solution._id?.toString(),
            challengeId: challenge._id?.toString(),
            deadline: deadline.toISOString(),
            now: now.toISOString(),
            traceId
          });
          
          await this.updateEvaluationStatus(evaluationId, 'pending', traceId, {
            failureReason: 'Challenge deadline has not passed yet'
          });
          
          return;
        }
      }
      
      // Log processing start
      logger.info(`Starting evaluation processing sequence`, {
        evaluationId,
        solutionId: solution._id?.toString(),
        traceId
      });
      
      // Use iterative pipeline to ensure thorough evaluation
      // The pipeline will analyze the challenge and solution multiple times
      // for better understanding before making decisions
      const pipelineResult = await this.pipelineController.executeIterativePipeline(solution, 2);
      
      if (!pipelineResult.success) {
        logger.error(`Evaluation pipeline failed`, {
          evaluationId,
          solutionId: solution._id?.toString(),
          reason: pipelineResult.reason,
          stoppedAt: pipelineResult.stoppedAt,
          traceId
        });
        
        await this.updateEvaluationStatus(evaluationId, 'failed', traceId, {
          failureReason: pipelineResult.reason || 'Pipeline failed'
        });
        
        // Update solution status based on where the pipeline failed
        await this.withTransaction(async (session) => {
          await this.updateSolutionStatusFromPipelineResult(solution, pipelineResult, session);
        });
        
        return;
      }
      
      // Store pipeline results in evaluation
      const updateData: Record<string, any> = {};
      
      // Map pipeline results to evaluation fields
      // Try both the new agent naming convention and the old one
      if (pipelineResult.results.SpamFilteringAgent) {
        updateData.spamFiltering = pipelineResult.results.SpamFilteringAgent.result;
      } else if (pipelineResult.results.spamFiltering) {
        updateData.spamFiltering = pipelineResult.results.spamFiltering.result;
      }
      
      if (pipelineResult.results.RequirementsComplianceAgent) {
        updateData.requirementsCompliance = pipelineResult.results.RequirementsComplianceAgent.result;
      } else if (pipelineResult.results.requirementsCompliance) {
        updateData.requirementsCompliance = pipelineResult.results.requirementsCompliance.result;
      }
      
      if (pipelineResult.results.CodeQualityAgent) {
        updateData.codeQuality = pipelineResult.results.CodeQualityAgent.result;
      } else if (pipelineResult.results.codeQuality) {
        updateData.codeQuality = pipelineResult.results.codeQuality.result;
      }
      
      if (pipelineResult.results.ScoringFeedbackAgent) {
        updateData.scoringFeedback = pipelineResult.results.ScoringFeedbackAgent.result;
      } else if (pipelineResult.results.scoringFeedback) {
        updateData.scoringFeedback = pipelineResult.results.scoringFeedback.result;
      }
      
      // Update evaluation status and data
      await this.updateEvaluationStatus(evaluationId, 'completed', traceId, {
        ...updateData,
        completedAt: new Date()
      });
      
      // Update solution status with evaluation results
      await this.withTransaction(async (session) => {
        await this.updateSolutionStatusFromPipelineResult(solution, pipelineResult, session);
      });
      
      logger.info(`Evaluation processing sequence completed successfully`, {
        evaluationId,
        solutionId: solution._id?.toString(),
        traceId,
        processingTimeMs: pipelineResult.processingTimeMs
      });
    } catch (error) {
      logger.error(`Error processing evaluation sequence`, {
        evaluationId,
        traceId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      // Update evaluation status to failed
      await this.updateEvaluationStatus(evaluationId, 'failed', traceId, {
        failureReason: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Update solution status based on pipeline result
   * @param solution - The solution to update
   * @param pipelineResult - The pipeline result
   * @param session - MongoDB session for transactions
   */
  private async updateSolutionStatusFromPipelineResult(
    solution: ISolution,
    pipelineResult: PipelineResult,
    session: ClientSession
  ): Promise<void> {
    try {
      // Extract key metrics
      const metrics = this.pipelineController.getMetricsFromResults(pipelineResult.results);
      
      // Prepare solution update
      const updateData: Record<string, any> = {
        lastUpdatedAt: new Date()
      };
      
      // Determine solution status based on final decision
      switch (pipelineResult.finalDecision) {
        case EvaluationDecision.PASS:
          // Solution passed all checks and is sent to architect for review
          updateData.status = SolutionStatus.UNDER_REVIEW;
          updateData.aiScore = metrics.averageScore;
          
          // Prepare solution for architect review
          solution = this.pipelineController.prepareSolutionForArchitectReview(solution, pipelineResult);
          
          // Store the prepared solution data
          Object.assign(updateData, {
            feedback: solution.feedback,
            evaluationScores: solution.evaluationScores || {},
            reviewPriority: solution.reviewPriority || 'medium'
          });
          
          logger.info(`Solution passed AI evaluation and is ready for architect review`, {
            solutionId: solution._id?.toString(),
            score: metrics.averageScore
          });
          break;
          
        case EvaluationDecision.FAIL:
          // Solution failed at spam filtering or requirements compliance stage
          // Student will receive feedback and can't resubmit after the deadline
          updateData.status = SolutionStatus.REJECTED;
          updateData.rejectionReason = pipelineResult.reason || 'Failed AI evaluation';
          
          // Set feedback from the failing stage
          if (pipelineResult.stoppedAt === 'SpamFilteringAgent' && pipelineResult.results.SpamFilteringAgent) {
            updateData.feedback = pipelineResult.results.SpamFilteringAgent.result.feedback;
          } else if (pipelineResult.stoppedAt === 'spamFiltering' && pipelineResult.results.spamFiltering) {
            updateData.feedback = pipelineResult.results.spamFiltering.result.feedback;
          } else if (pipelineResult.stoppedAt === 'RequirementsComplianceAgent' && pipelineResult.results.RequirementsComplianceAgent) {
            updateData.feedback = pipelineResult.results.RequirementsComplianceAgent.result.feedback;
          } else if (pipelineResult.stoppedAt === 'requirementsCompliance' && pipelineResult.results.requirementsCompliance) {
            updateData.feedback = pipelineResult.results.requirementsCompliance.result.feedback;
          } else {
            updateData.feedback = 'Your solution did not meet the required criteria.';
          }
          
          logger.info(`Solution rejected by AI evaluation`, {
            solutionId: solution._id?.toString(),
            stoppedAt: pipelineResult.stoppedAt,
            reason: pipelineResult.reason
          });
          break;
          
        case EvaluationDecision.REVIEW:
        case EvaluationDecision.ERROR:
          // Mark for architect review in case of uncertainty or error
          updateData.status = SolutionStatus.UNDER_REVIEW;
          updateData.reviewPriority = 'high'; // Prioritize manual review for uncertain cases
          updateData.notes = `Flagged for review: ${pipelineResult.reason || 'Evaluation uncertainty'}`;
          
          logger.info(`Solution marked for priority architect review due to evaluation uncertainty`, {
            solutionId: solution._id?.toString(),
            finalDecision: pipelineResult.finalDecision
          });
          break;
      }
      
      // Update the solution
      await Solution.findByIdAndUpdate(
        solution._id,
        updateData,
        { new: true, session }
      );
    } catch (error) {
      logger.error(`Error updating solution status from pipeline result`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
      
      throw error;
    }
  }

  /**
   * Get the evaluation result for a solution
   * @param solutionId - The ID of the solution
   * @returns The evaluation result
   */
  public async getEvaluationResult(solutionId: string): Promise<IAIEvaluation> {
    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }
    
    const sanitizedSolutionId = MongoSanitizer.sanitizeObjectId(solutionId);
    
    try {
      const evaluation = await AIEvaluation.findOne({ 
        solution: sanitizedSolutionId 
      }).populate('solution');
      
      if (!evaluation) {
        logger.warn(`Evaluation not found for solution`, { 
          solutionId: sanitizedSolutionId 
        });
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Evaluation not found for this solution',
          true,
          'EVALUATION_NOT_FOUND'
        );
      }
      
      return evaluation;
    } catch (error) {
      logger.error(`Error getting evaluation result`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      if (error instanceof ApiError) throw error;
      
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to get evaluation result',
        true,
        'EVALUATION_RESULT_ERROR'
      );
    }
  }

  /**
   * Get the current status of an evaluation for a solution
   * @param solutionId - The ID of the solution
   * @returns Object containing evaluation status information
   */
  public async getEvaluationStatus(solutionId: string): Promise<IEvaluationStatus> {
    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }

    const sanitizedSolutionId = MongoSanitizer.sanitizeObjectId(solutionId);

    try {
      const evaluation = await AIEvaluation.findOne({
        solution: sanitizedSolutionId
      });

      if (!evaluation) {
        logger.warn(`No evaluation found for status check`, {
          solutionId: sanitizedSolutionId
        });
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'No evaluation found for this solution',
          true,
          'EVALUATION_NOT_FOUND'
        );
      }

      // Calculate progress based on completed steps
      let progress = 0;
      let currentStage: string | null = null;

      // Define evaluation stages in order
      const stages: IEvaluationStage[] = [
        { name: 'Spam Filtering', field: 'spamFiltering', weight: 0.1 },
        { name: 'Requirements Compliance', field: 'requirementsCompliance', weight: 0.3 },
        { name: 'Code Quality', field: 'codeQuality', weight: 0.3 },
        { name: 'Scoring & Feedback', field: 'scoringFeedback', weight: 0.3 }
      ];

      // Calculate progress based on completed stages
      let accumulatedProgress = 0;
      let foundCurrentStage = false;

      for (const stage of stages) {
        const fieldValue = evaluation[stage.field];
        if (fieldValue) {
          // This stage is complete
          accumulatedProgress += stage.weight;
        } else if (!foundCurrentStage) {
          // First incomplete stage we find is the current one
          currentStage = stage.name;
          foundCurrentStage = true;
        }
      }

      progress = Math.round(accumulatedProgress * 100);

      // Handle special cases
      if (evaluation.status === 'completed') {
        progress = 100;
        currentStage = 'Completed';
      } else if (evaluation.status === 'failed') {
        currentStage = 'Failed';
      } else if (evaluation.status === 'pending') {
        currentStage = 'Pending';
        progress = 0;
      }

      // Estimate completion time
      let estimatedCompletionTime: Date | null = null;
      if (evaluation.status === 'in_progress' && evaluation.createdAt) {
        // Use configured standard evaluation duration
        const elapsedMs = Date.now() - evaluation.createdAt.getTime();
        const remainingMs = (this.STANDARD_EVALUATION_DURATION_MS * (1 - (progress / 100))) - elapsedMs;

        if (remainingMs > 0) {
          estimatedCompletionTime = new Date(Date.now() + remainingMs);
        } else {
          estimatedCompletionTime = new Date(Date.now() + 60000); // Default to 1 minute if calculation is negative
        }
      }

      return {
        status: evaluation.status,
        progress,
        startedAt: evaluation.createdAt,
        completedAt: evaluation.completedAt || null,
        currentStage,
        estimatedCompletionTime
      };
    } catch (error) {
      logger.error(`Error getting evaluation status`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to get evaluation status',
        true,
        'EVALUATION_STATUS_ERROR'
      );
    }
  }

  /**
   * Get analytics data about AI evaluations
   * @param options - Analytics filter options
   * @returns Analytics data
   */
  public async getEvaluationAnalytics(options: IEvaluationAnalyticsOptions): Promise<IEvaluationAnalyticsResult> {
    try {
      const { startDate, endDate, challengeId, groupBy = 'day', limit = 50 } = options;

      // Build query filters
      const queryFilters: Record<string, any> = {};

      // Date range filters
      if (startDate) {
        queryFilters.createdAt = queryFilters.createdAt || {};
        queryFilters.createdAt.$gte = startDate;
      }

      if (endDate) {
        queryFilters.createdAt = queryFilters.createdAt || {};
        queryFilters.createdAt.$lte = endDate;
      }

      // Challenge filter requires joining with solutions
      if (challengeId) {
        // We'll implement the join in a future PR
        // For now, log that this filter isn't implemented
        logger.info(`Challenge-specific analytics not yet implemented`, { challengeId });
      }

      // Basic analytics - status counts
      const statusCounts = await AIEvaluation.aggregate([
        { $match: queryFilters },
        { $group: { _id: '$status', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);

      // Time-based analytics
      let timeGrouping: any = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } };
      if (groupBy === 'week') {
        timeGrouping = { $dateToString: { format: '%Y-%U', date: '$createdAt' } };
      } else if (groupBy === 'month') {
        timeGrouping = { $dateToString: { format: '%Y-%m', date: '$createdAt' } };
      }

      const timeAnalytics = await AIEvaluation.aggregate([
        { $match: queryFilters },
        {
          $group: {
            _id: timeGrouping,
            count: { $sum: 1 },
            completed: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            failed: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            }
          }
        },
        { $sort: { _id: -1 } },
        { $limit: limit }
      ]);

      // Performance metrics
      const performanceQuery = await AIEvaluation.aggregate([
        {
          $match: {
            ...queryFilters,
            status: 'completed',
            startedAt: { $exists: true },
            completedAt: { $exists: true }
          }
        },
        {
          $project: {
            processingTimeMs: {
              $subtract: ['$completedAt', '$startedAt']
            }
          }
        },
        {
          $group: {
            _id: null,
            avgTime: { $avg: '$processingTimeMs' },
            minTime: { $min: '$processingTimeMs' },
            maxTime: { $max: '$processingTimeMs' },
            count: { $sum: 1 }
          }
        }
      ]);

      const performance = performanceQuery[0] || {
        avgTime: 0,
        minTime: 0,
        maxTime: 0,
        count: 0
      };

      return {
        summary: {
          total: statusCounts.reduce((sum, item) => sum + item.count, 0),
          byStatus: statusCounts.reduce<Record<string, number>>((result, item) => {
            result[item._id] = item.count;
            return result;
          }, {})
        },
        timeAnalytics,
        performance
      };
    } catch (error) {
      logger.error('Error getting evaluation analytics', {
        error: error instanceof Error ? error.message : String(error),
        options
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve evaluation analytics',
        true,
        'ANALYTICS_ERROR'
      );
    }
  }

  /**
   * Retry a failed evaluation
   * @param solutionId - ID of the solution to retry evaluation for
   * @param options - Retry options
   * @param userId - ID of user initiating the retry
   * @returns Updated evaluation record
   */
  public async retryEvaluation(
    solutionId: string,
    options: IEvaluationRetryOptions,
    userId: string
  ): Promise<IAIEvaluation> {
    const { forceRestart = false, priority, skipSteps } = options;

    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }

    const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');
    const traceId = uuidv4();

    try {
      return await this.withTransaction(async (session) => {
        // Find the existing evaluation
        const evaluation = await AIEvaluation.findOne({
          solution: sanitizedSolutionId
        }).session(session);

        if (!evaluation) {
          logger.warn(`No evaluation found to retry`, {
            solutionId: sanitizedSolutionId,
            traceId
          });

          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            'No evaluation found for this solution',
            true,
            'EVALUATION_NOT_FOUND'
          );
        }

        // Check if evaluation is in a state that can be retried
        if (!forceRestart && evaluation.status !== 'failed') {
          logger.warn(`Cannot retry evaluation that is not in failed state`, {
            solutionId: sanitizedSolutionId,
            currentStatus: evaluation.status,
            traceId
          });

          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Cannot retry evaluation with status '${evaluation.status}'. Only failed evaluations can be retried.`,
            true,
            'INVALID_EVALUATION_STATE'
          );
        }

        // Reset evaluation to pending state
        evaluation.status = 'pending';
        evaluation.failureReason = undefined;
        evaluation.retryCount = (evaluation.retryCount || 0) + 1;
        evaluation.updatedAt = new Date();

        // Store retry metadata
        evaluation.metadata = {
          ...(evaluation.metadata || {}),
          retryRequested: {
            by: userId,
            at: new Date(),
            priority,
            skipSteps
          },
          traceId
        };

        await evaluation.save({ session });

        logger.info(`Evaluation retry requested`, {
          solutionId: sanitizedSolutionId,
          evaluationId: evaluation._id?.toString(),
          by: userId,
          traceId
        });

        // Schedule processing and wait for it to start
        await this.scheduleEvaluationProcessing(evaluation._id?.toString(), traceId);

        return evaluation;
      });
    } catch (error) {
      logger.error(`Error retrying evaluation`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error),
        traceId
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retry evaluation',
        true,
        'EVALUATION_RETRY_ERROR'
      );
    }
  }

  /**
   * Run the evaluation pipeline directly for a solution
   * Provides direct access to the pipeline controller
   * @param solutionId - The ID of the solution to evaluate
   * @returns Pipeline execution result
   */
  public async runEvaluationPipeline(solutionId: string): Promise<PipelineResult> {
    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }
    
    const sanitizedSolutionId = MongoSanitizer.sanitizeObjectId(solutionId);
    
    try {
      // Fetch the solution with full details
      const solution = await Solution.findById(sanitizedSolutionId)
        .populate('challenge');
      
      if (!solution) {
        logger.warn(`Solution not found for pipeline execution`, { 
          solutionId: sanitizedSolutionId
        });
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Solution not found',
          true,
          'SOLUTION_NOT_FOUND'
        );
      }
      
      // Validate GitHub repository URL
      const sanitizedGitHubUrl = MongoSanitizer.sanitizeGitHubUrl(solution.submissionUrl);
      if (!sanitizedGitHubUrl) {
        logger.warn(`Invalid GitHub repository URL`, {
          solutionId: sanitizedSolutionId,
          submissionUrl: solution.submissionUrl
        });
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Solution must have a valid GitHub repository URL',
          true,
          'INVALID_GITHUB_URL'
        );
      }

      // Execute the pipeline directly 
      const pipelineResult = await this.pipelineController.executePipeline(solution);

      logger.info(`Direct pipeline execution completed for solution`, {
        solutionId: sanitizedSolutionId,
        success: pipelineResult.success,
        finalDecision: pipelineResult.finalDecision
      });

      return pipelineResult;
    } catch (error) {
      logger.error(`Error running evaluation pipeline`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      if (error instanceof ApiError) throw error;
      
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to run evaluation pipeline',
        true,
        'PIPELINE_EXECUTION_ERROR'
      );
    }
  }

  /**
   * Process AI evaluations for all solutions of a specific challenge
   * Used when a challenge deadline is reached
   * @param challengeId - The ID of the challenge
   * @returns Processing results
   */
  public async processEvaluationsForChallenge(
    challengeId: string
  ): Promise<{
    totalSolutions: number;
    processed: number;
    failed: number;
    processingTimeMs: number;
  }> {
    const startTime = Date.now();
    const traceId = uuidv4();
    
    try {
      logger.info(`Processing AI evaluations for all solutions of challenge ${challengeId}`, {
        challengeId,
        traceId
      });
      
      // Validate challengeId
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(challengeId, 'challenge');
      
      // Find all submitted solutions for this challenge
      const solutions = await Solution.find({
        challenge: sanitizedChallengeId,
        status: SolutionStatus.SUBMITTED
      }).lean();
      
      logger.info(`Found ${solutions.length} solutions for challenge ${challengeId}`, {
        challengeId,
        count: solutions.length,
        traceId
      });
      
      // Extract solution IDs directly from MongoDB query results
      // Cast solutions to any to avoid TypeScript errors with _id access
      const solutionIds = solutions.map((solution: any) => solution._id.toString());
      
      // Process solutions in parallel with batch control
      const batchSize = 5; // Process 5 solutions at a time to avoid overwhelming the system
      const results = {
        totalSolutions: solutions.length,
        processed: 0,
        failed: 0,
        processingTimeMs: 0
      };
      
      // Process in batches
      for (let i = 0; i < solutionIds.length; i += batchSize) {
        const batchIds = solutionIds.slice(i, i + batchSize);
        
        // Process batch in parallel
        const batchResults = await Promise.allSettled(
          batchIds.map(solutionId => this.startEvaluation(solutionId))
        );
        
        // Count successes and failures
        batchResults.forEach(result => {
          if (result.status === 'fulfilled') {
            results.processed++;
          } else {
            results.failed++;
            logger.error(`Failed to start evaluation for solution in batch`, {
              challengeId,
              error: result.reason instanceof Error ? result.reason.message : String(result.reason),
              traceId
            });
          }
        });
        
        // Log batch progress
        logger.info(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(solutionIds.length / batchSize)}`, {
          challengeId,
          batchSize: batchIds.length,
          successCount: batchResults.filter(r => r.status === 'fulfilled').length,
          failureCount: batchResults.filter(r => r.status === 'rejected').length,
          traceId
        });
      }
      
      // Calculate total processing time
      results.processingTimeMs = Date.now() - startTime;
      
      logger.info(`Completed processing AI evaluations for challenge ${challengeId}`, {
        ...results,
        traceId
      });
      
      return results;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      
      logger.error(`Error processing AI evaluations for challenge ${challengeId}`, {
        challengeId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        processingTimeMs: processingTime,
        traceId
      });
      
      if (error instanceof ApiError) throw error;
      
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        `Failed to process evaluations for challenge: ${error instanceof Error ? error.message : String(error)}`,
        true,
        'CHALLENGE_EVALUATION_ERROR'
      );
    }
  }
}

// Export singleton instance for use
export const aiEvaluationService = new AIEvaluationService();