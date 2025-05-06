import { BaseService } from '../BaseService';
import { Types, ClientSession } from 'mongoose';
import { AIEvaluation, Solution } from '../../models';
import {
  IAIEvaluation,
  ISolution,
  ISpamFilteringResult,
  IRequirementsComplianceResult,
  ICodeQualityResult,
  IScoringFeedbackResult,
  SolutionStatus,
  EvaluationDecision
} from '../../models/interfaces';
import { ApiError } from '../../utils/api.error';
import { logger } from '../../utils/logger';
import { HTTP_STATUS } from '../../models/interfaces';
import { AIAgentFactory } from './AIAgentFactory';
import { MongoSanitizer } from '../../utils/mongo.sanitize';
import { v4 as uuidv4 } from 'uuid';
import { EvaluationPipelineController, evaluationPipelineController } from './EvaluationPipelineController';

/**
 * Service for orchestrating the AI evaluation pipeline
 * Manages the sequential workflow and state transitions for GitHub repository submissions
 */
export class AIEvaluationService extends BaseService {
  private readonly agentFactory: AIAgentFactory;
  private readonly pipelineController: EvaluationPipelineController;

  // Maximum number of retries for evaluation 
  private readonly MAX_RETRY_COUNT = 3;
  
  // Sequential order of agent execution
  private readonly EVALUATION_SEQUENCE = [
    'SpamFilteringAgent',
    'RequirementsComplianceAgent',
    'CodeQualityAgent',
    'ScoringFeedbackAgent'
  ];

  /**
   * Constructor
   */
  constructor() {
    super();
    this.agentFactory = AIAgentFactory.getInstance();
    this.pipelineController = evaluationPipelineController;
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
    if (!Types.ObjectId.isValid(sanitizedSolutionId)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid solution ID format',
        true,
        'INVALID_SOLUTION_ID'
      );
    }

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
        if (!solution.submissionUrl || !sanitizedGitHubUrl) {
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
            if (!existingEvaluation.metadata) {
              existingEvaluation.metadata = {};
            }
            existingEvaluation.metadata.lastRetryAt = new Date();
            
            await existingEvaluation.save({ session });
            
            // Schedule the sequential processing 
            this.processEvaluationSequence(existingEvaluation._id?.toString())
              .catch(error => {
                logger.error(`Failed to process evaluation after retry`, {
                  solutionId: sanitizedSolutionId,
                  evaluationId: existingEvaluation._id?.toString(),
                  retryCount: existingEvaluation.retryCount,
                  error: error instanceof Error ? error.message : String(error),
                  traceId
                });
              });
            
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
        
        // Schedule the sequential processing
        this.processEvaluationSequence(evaluation._id?.toString())
          .catch(error => {
            logger.error(`Failed to process evaluation`, {
              solutionId: sanitizedSolutionId,
              evaluationId: evaluation._id?.toString(),
              error: error instanceof Error ? error.message : String(error),
              traceId
            });
          });
        
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
   * Process evaluation in a sequential workflow
   * Each agent processes in order and passes results to the next agent
   * @param evaluationId - The ID of the evaluation to process
   */
  private async processEvaluationSequence(evaluationId: string | undefined): Promise<void> {
    if (!evaluationId) {
      logger.error('Missing evaluation ID for processing');
      return;
    }
    
    const traceId = uuidv4();
    
    try {
      logger.debug(`Starting sequential evaluation workflow`, { 
        evaluationId,
        traceId 
      });
      
      // Update evaluation status to in_progress
      await this.withTransaction(async (session) => {
        const evaluation = await AIEvaluation.findById(evaluationId).session(session);
        
        if (!evaluation) {
          logger.warn(`Evaluation not found for processing`, { 
            evaluationId,
            traceId 
          });
          return;
        }
        
        if (evaluation.status !== 'pending') {
          logger.warn(`Evaluation not in pending state, skipping`, {
            evaluationId,
            status: evaluation.status,
            traceId
          });
          return;
        }
        
        evaluation.status = 'in_progress';
        
        if (!evaluation.metadata) {
          evaluation.metadata = {};
        }
        evaluation.metadata.processingStartedAt = new Date();
        evaluation.metadata.traceId = traceId;
        
        await evaluation.save({ session });
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
        
        await this.markEvaluationFailed(
          evaluationId, 
          'Evaluation or solution not found', 
          traceId
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
      
      // Save results to the evaluation record
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
        if (!evalToUpdate.metadata) {
          evalToUpdate.metadata = {};
        }
        
        evalToUpdate.metadata.pipelineResult = {
          finalDecision: pipelineResult.finalDecision,
          pipelineCompleted: pipelineResult.pipelineCompleted,
          processingTimeMs: pipelineResult.processingTimeMs,
          stoppedAt: pipelineResult.stoppedAt,
          reason: pipelineResult.reason
        };
        
        // Get the metrics from the pipeline results
        const metrics = this.pipelineController.getMetricsFromResults(pipelineResult.results);
        evalToUpdate.metadata.metrics = metrics;
        
        await evalToUpdate.save({ session });
      });
      
      // Update solution status based on pipeline result
      await this.updateSolutionStatusFromPipelineResult(solution, pipelineResult);
      
      // Mark evaluation as completed
      if (!pipelineResult.success) {
        await this.markEvaluationFailed(
          evaluationId,
          pipelineResult.reason || 'Pipeline execution failed',
          traceId
        );
      } else {
        await this.completeEvaluation(evaluationId, traceId);
      }
    } catch (error) {
      logger.error(`Error in evaluation sequential processing`, {
        evaluationId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        traceId
      });
      
      await this.markEvaluationFailed(
        evaluationId,
        error instanceof Error ? error.message : 'Unknown error',
        traceId
      );
    }
  }
  
  /**
   * Update solution status based on pipeline result
   * @param solution - The solution to update
   * @param pipelineResult - The result from the pipeline
   */
  private async updateSolutionStatusFromPipelineResult(
    solution: ISolution,
    pipelineResult: ReturnType<typeof this.pipelineController.executePipeline> extends Promise<infer T> ? T : never
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
              pipelineResult.results.scoringFeedback.result.score >= 70) {
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
        });
        
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
      // Don't throw here - this is a side effect and shouldn't fail the main workflow
    }
  }
  
  /**
   * Mark an evaluation as completed
   * @param evaluationId - The ID of the evaluation
   * @param traceId - The trace ID for logging
   */
  private async completeEvaluation(evaluationId: string, traceId: string): Promise<void> {
    try {
      await this.withTransaction(async (session) => {
        const evaluation = await AIEvaluation.findById(evaluationId).session(session);
        
        if (!evaluation) {
          logger.warn(`Evaluation not found for completion`, { 
            evaluationId,
            traceId 
          });
          return;
        }
        
        evaluation.status = 'completed';
        evaluation.completedAt = new Date();
        
        if (!evaluation.metadata) {
          evaluation.metadata = {};
        }
        evaluation.metadata.completedAt = new Date();
        
        await evaluation.save({ session });
        
        logger.info(`Completed evaluation`, {
          evaluationId,
          traceId
        });
      });
    } catch (error) {
      logger.error(`Error completing evaluation`, {
        evaluationId,
        error: error instanceof Error ? error.message : String(error),
        traceId
      });
    }
  }
  
  /**
   * Mark an evaluation as failed
   * @param evaluationId - The ID of the evaluation
   * @param reason - The reason for failure
   * @param traceId - The trace ID for logging
   */
  private async markEvaluationFailed(
    evaluationId: string,
    reason: string,
    traceId: string
  ): Promise<void> {
    try {
      await this.withTransaction(async (session) => {
        const evaluation = await AIEvaluation.findById(evaluationId).session(session);
        
        if (!evaluation) {
          logger.warn(`Evaluation not found for failure marking`, { 
            evaluationId,
            traceId 
          });
          return;
        }
        
        evaluation.status = 'failed';
        evaluation.failureReason = reason;
        
        if (!evaluation.metadata) {
          evaluation.metadata = {};
        }
        evaluation.metadata.failedAt = new Date();
        evaluation.metadata.failureReason = reason;
        
        await evaluation.save({ session });
        
        logger.warn(`Marked evaluation as failed`, {
          evaluationId,
          reason,
          traceId
        });
      });
    } catch (error) {
      logger.error(`Error marking evaluation as failed`, {
        evaluationId,
        reason,
        error: error instanceof Error ? error.message : String(error),
        traceId
      });
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
    if (!Types.ObjectId.isValid(sanitizedSolutionId)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid solution ID format',
        true,
        'INVALID_SOLUTION_ID'
      );
    }
    
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
  public async getEvaluationStatus(solutionId: string): Promise<{
    status: string;
    progress: number;
    startedAt: Date | null;
    completedAt: Date | null;
    currentStage: string | null;
    estimatedCompletionTime: Date | null;
  }> {
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
      let currentStage = null;

      // Define evaluation stages in order
      const stages = [
        { name: 'Spam Filtering', field: 'spamFiltering', weight: 0.1 },
        { name: 'Requirements Compliance', field: 'requirementsCompliance', weight: 0.3 },
        { name: 'Code Quality', field: 'codeQuality', weight: 0.3 },
        { name: 'Scoring & Feedback', field: 'scoringFeedback', weight: 0.3 }
      ];

      // Calculate progress based on completed stages
      let accumulatedProgress = 0;
      let foundCurrentStage = false;

      for (const stage of stages) {
        // @ts-ignore - dynamic access to evaluation properties
        if (evaluation[stage.field]) {
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
        // Rough estimate: typical evaluation takes about 5 minutes
        const estimatedDurationMs = 5 * 60 * 1000;
        const elapsedMs = Date.now() - evaluation.createdAt.getTime();
        const remainingMs = (estimatedDurationMs * (1 - (progress / 100))) - elapsedMs;

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
  public async getEvaluationAnalytics(options: {
    startDate?: Date;
    endDate?: Date;
    challengeId?: string;
    groupBy?: string;
    limit?: number;
  }): Promise<any> {
    try {
      const { startDate, endDate, challengeId, groupBy = 'day', limit = 50 } = options;

      // Build query filters
      const queryFilters: any = {};

      // Date range filters
      if (startDate) {
        queryFilters.createdAt = queryFilters.createdAt || {};
        queryFilters.createdAt.$gte = startDate;
      }

      if (endDate) {
        queryFilters.createdAt = queryFilters.createdAt || {};
        queryFilters.createdAt.$lte = endDate;
      }

      // Challenge filter
      if (challengeId) {
        // For challenge-specific analytics, we need to join with solutions
        // This requires a more complex aggregation
      }

      // Basic analytics - status counts
      const statusCounts = await AIEvaluation.aggregate([
        { $match: queryFilters },
        { $group: { _id: '$status', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);

      // Time-based analytics
      let timeGrouping = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } };
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
      const averageProcessingTime = await AIEvaluation.aggregate([
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

      return {
        summary: {
          total: statusCounts.reduce((sum, item) => sum + item.count, 0),
          byStatus: statusCounts.reduce((result, item) => {
            result[item._id] = item.count;
            return result;
          }, {})
        },
        timeAnalytics,
        performance: averageProcessingTime[0] || {
          avgTime: 0,
          minTime: 0,
          maxTime: 0,
          count: 0
        }
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
    options: {
      forceRestart?: boolean;
      priority?: string;
      skipSteps?: string[];
    },
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
          ...evaluation.metadata,
          retryRequested: {
            by: userId,
            at: new Date(),
            priority,
            skipSteps
          }
        };

        await evaluation.save({ session });

        logger.info(`Evaluation retry requested`, {
          solutionId: sanitizedSolutionId,
          evaluationId: evaluation._id?.toString(),
          by: userId,
          traceId
        });

        // Schedule processing asynchronously
        setTimeout(() => {
          this.processEvaluationSequence(evaluation._id?.toString())
            .catch(error => {
              logger.error(`Failed to process retry`, {
                evaluationId: evaluation._id?.toString(),
                error: error instanceof Error ? error.message : String(error),
                traceId
              });
            });
        }, 100);

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
  public async runEvaluationPipeline(solutionId: string): Promise<ReturnType<typeof this.pipelineController.executePipeline> extends Promise<infer T> ? T : never> {
    if (!solutionId) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required',
        true,
        'MISSING_SOLUTION_ID'
      );
    }
    
    const sanitizedSolutionId = MongoSanitizer.sanitizeObjectId(solutionId);
    if (!Types.ObjectId.isValid(sanitizedSolutionId)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid solution ID format',
        true,
        'INVALID_SOLUTION_ID'
      );
    }
    
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
      if (!solution.submissionUrl || !sanitizedGitHubUrl) {
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
}

export const aiEvaluationService = new AIEvaluationService();