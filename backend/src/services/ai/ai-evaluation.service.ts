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
  
  // Score thresholds
  private readonly ARCHITECT_REVIEW_THRESHOLD: number;

  /**
   * Constructor
   */
  constructor() {
    super();
    this.pipelineController = evaluationPipelineController;
    
    // Get configuration values with defaults
    this.MAX_RETRY_COUNT = config.evaluation?.maxRetryCount || 3;
    this.STANDARD_EVALUATION_DURATION_MS = config.evaluation?.standardDurationMs || 5 * 60 * 1000;
    this.ARCHITECT_REVIEW_THRESHOLD = config.evaluation?.architectReviewThreshold || 70;
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
   * Process evaluation in a sequential workflow
   * Each agent processes in order and passes results to the next agent
   * @param evaluationId - The ID of the evaluation to process
   * @param traceId - Trace ID for logging
   */
  private async processEvaluationSequence(evaluationId: string, traceId: string): Promise<void> {
    try {
      logger.debug(`Starting sequential evaluation workflow`, { 
        evaluationId,
        traceId 
      });
      
      // Fetch the solution with full details
      const evaluation = await AIEvaluation.findById(evaluationId)
        .populate({
          path: 'solution',
          populate: {
            path: 'challenge'
          }
        });
      
      if (!evaluation || !evaluation.solution) {
        logger.error(`Evaluation or solution not found`, { 
          evaluationId,
          traceId 
        });
        
        await this.updateEvaluationStatus(
          evaluationId, 
          'failed', 
          traceId, 
          { failureReason: 'Evaluation or solution not found' }
        );
        return;
      }
      
      const solution = evaluation.solution as ISolution;

      // Execute the evaluation pipeline using the pipeline controller
      const pipelineResult = await this.pipelineController.executePipeline(solution);
      
      logger.info(`Pipeline execution completed`, {
        evaluationId,
        solutionId: solution._id?.toString(),
        success: pipelineResult.success,
        completed: pipelineResult.pipelineCompleted,
        finalDecision: pipelineResult.finalDecision,
        processingTimeMs: pipelineResult.processingTimeMs,
        traceId: pipelineResult.traceId || traceId
      });
      
      // Save results to the evaluation record and update solution status in a single transaction
      await this.withTransaction(async (session) => {
        const evalToUpdate = await AIEvaluation.findById(evaluationId).session(session);
        
        if (!evalToUpdate) {
          logger.warn(`Evaluation not found for updating results`, { 
            evaluationId,
            traceId 
          });
          return;
        }
        
        // Update each result if available
        if (pipelineResult.results.spamFiltering) {
          evalToUpdate.spamFiltering = pipelineResult.results.spamFiltering.result;
        }
        
        if (pipelineResult.results.requirementsCompliance) {
          evalToUpdate.requirementsCompliance = pipelineResult.results.requirementsCompliance.result;
        }
        
        if (pipelineResult.results.codeQuality) {
          evalToUpdate.codeQuality = pipelineResult.results.codeQuality.result;
        }
        
        if (pipelineResult.results.scoringFeedback) {
          evalToUpdate.scoringFeedback = pipelineResult.results.scoringFeedback.result;
        }
        
        // Update metadata
        evalToUpdate.metadata = {
          ...(evalToUpdate.metadata || {}),
          pipelineResult: {
            finalDecision: pipelineResult.finalDecision,
            pipelineCompleted: pipelineResult.pipelineCompleted,
            processingTimeMs: pipelineResult.processingTimeMs,
            stoppedAt: pipelineResult.stoppedAt,
            reason: pipelineResult.reason
          }
        };
        
        // Get the metrics from the pipeline results
        const metrics = this.pipelineController.getMetricsFromResults(pipelineResult.results);
        evalToUpdate.metadata.metrics = metrics;
        
        // Update evaluation status
        if (!pipelineResult.success) {
          evalToUpdate.status = 'failed';
          evalToUpdate.failureReason = pipelineResult.reason || 'Pipeline execution failed';
        } else {
          evalToUpdate.status = 'completed';
          evalToUpdate.completedAt = new Date();
        }
        
        await evalToUpdate.save({ session });
        
        // Also update the solution status in the same transaction
        await this.updateSolutionStatusFromPipelineResult(solution, pipelineResult, session);
      });
      
    } catch (error) {
      logger.error(`Error in evaluation sequential processing`, {
        evaluationId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        traceId
      });
      
      await this.updateEvaluationStatus(
        evaluationId,
        'failed',
        traceId, 
        { 
          failureReason: error instanceof Error ? error.message : 'Unknown error',
          failedAt: new Date()
        }
      );
    }
  }
  
  /**
   * Update solution status based on pipeline result
   * @param solution - The solution to update
   * @param pipelineResult - The result from the pipeline
   * @param session - Mongoose session for transactional updates
   */
  private async updateSolutionStatusFromPipelineResult(
    solution: ISolution,
    pipelineResult: PipelineResult,
    session: ClientSession
  ): Promise<void> {
    try {
      // Determine the new status based on the pipeline result
      let newStatus: SolutionStatus = solution.status;
      let feedback: string | undefined = undefined;
      
      // Get the last agent result for feedback
      const lastAgentResult = pipelineResult.results.scoringFeedback ||
        pipelineResult.results.codeQuality ||
        pipelineResult.results.requirementsCompliance ||
        pipelineResult.results.spamFiltering;
      
      if (lastAgentResult) {
        feedback = lastAgentResult.result.feedback;
      }
      
      // Determine status based on final decision
      switch (pipelineResult.finalDecision) {
        case EvaluationDecision.FAIL:
          newStatus = SolutionStatus.REJECTED;
          break;
        
        case EvaluationDecision.REVIEW:
          // If review is requested, put in queue for architect review
          newStatus = SolutionStatus.CLAIMED;
          break;
        
        case EvaluationDecision.PASS:
          // If passing with good score, mark for architect review
          if (pipelineResult.results.scoringFeedback && 
              pipelineResult.results.scoringFeedback.result.score >= this.ARCHITECT_REVIEW_THRESHOLD) {
            newStatus = SolutionStatus.CLAIMED;
          } else {
            // Otherwise, approve automatically 
            newStatus = SolutionStatus.APPROVED;
          }
          break;
      }
      
      // Only update if status has changed
      if (newStatus !== solution.status) {
        await Solution.findByIdAndUpdate(solution._id, {
          status: newStatus,
          feedback: feedback || 'Evaluated by AI system'
        }).session(session);
        
        logger.info(`Updated solution status based on pipeline result`, {
          solutionId: solution._id?.toString(),
          previousStatus: solution.status,
          newStatus,
          finalDecision: pipelineResult.finalDecision
        });
      }
    } catch (error) {
      logger.error(`Error updating solution status from pipeline result`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
      // Throw error to ensure transaction rollback
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