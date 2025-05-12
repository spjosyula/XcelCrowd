import { Response, NextFunction } from 'express';
import { BaseController } from './BaseController';
import { AIEvaluationService, aiEvaluationService } from '../services/ai/ai-evaluation.service';
import { catchAsync } from '../utils/catch.async';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/api.error';
import { UserRole } from '../models/interfaces';
import { HTTP_STATUS } from '../constants';
import { AuthRequest } from '../types/request.types';
import { MongoSanitizer } from '../utils/mongo.sanitize';

/**
 * Controller for AI Evaluation APIs
 * Extends BaseController for standardized response handling
 * Contains no business logic - delegates to AIEvaluationService
 */
export class AIEvaluationController extends BaseController {
  private readonly aiEvaluationService: AIEvaluationService;

  constructor() {
    super();
    this.aiEvaluationService = aiEvaluationService;
  }

  /**
   * Start the AI evaluation process for a solution
   * @route POST /api/ai-evaluation/solutions/:solutionId/evaluate
   * @access Private - Admin or Architect only
   */
  public startEvaluation = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization with proper role enums
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'starting AI evaluations');

      const { solutionId } = req.params;

      // Validate ObjectId format using MongoSanitizer
      MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Log the evaluation request with structured data
      this.logAction('start-ai-evaluation', req.user!.userId, {
        solutionId,
        requestedAt: new Date().toISOString()
      });

      // Add performance tracking
      const startTime = Date.now();

      // Start the evaluation process via service
      const evaluation = await this.aiEvaluationService.startEvaluation(solutionId);

      // Log performance metrics
      const processingTime = Date.now() - startTime;
      logger.debug('AI evaluation request processing time', {
        solutionId,
        processingTimeMs: processingTime
      });

      this.sendSuccess(
        res,
        evaluation,
        'AI evaluation process started successfully'
      );
    }
  );

  /**
   * Get the AI evaluation result for a solution
   * @route GET /api/ai-evaluation/solutions/:solutionId/result
   * @access Private - Admin or Architect only
   */
  public getEvaluationResult = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'viewing AI evaluation results');

      const { solutionId } = req.params;

      // Validate ObjectId format using MongoSanitizer
      MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Log the evaluation request
      this.logAction('get-ai-evaluation', req.user!.userId, {
        solutionId,
        userRole: req.user!.role
      });

      // Get the evaluation result
      const evaluation = await this.aiEvaluationService.getEvaluationResult(solutionId);

      // Handle case where evaluation doesn't exist
      if (!evaluation) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'AI evaluation not found for this solution',
          true,
          'EVALUATION_NOT_FOUND'
        );
      }

      this.sendSuccess(
        res,
        evaluation,
        'AI evaluation result retrieved successfully'
      );
    }
  );

  /**
   * Check status of an ongoing evaluation
   * @route GET /api/ai-evaluation/solutions/:solutionId/status
   * @access Private - Admin or Architect only
   */
  public getEvaluationStatus = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'checking AI evaluation status');

      const { solutionId } = req.params;

      // Validate ObjectId format using MongoSanitizer
      MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Log the status check
      this.logAction('check-ai-evaluation-status', req.user!.userId, {
        solutionId
      });

      // Get status via service
      const status = await this.aiEvaluationService.getEvaluationStatus(solutionId);

      this.sendSuccess(
        res,
        status,
        'AI evaluation status retrieved successfully'
      );
    }
  );

  /**
 * Get analytics data about AI evaluations
 * @route GET /api/ai-evaluation/analytics
 * @access Private - Admin only
 */
  public getEvaluationAnalytics = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization (this is redundant since the route already has ADMIN_ONLY middleware,
      // but it's consistent with your other methods)
      this.verifyAuthorization(req, [UserRole.ADMIN], 'accessing AI evaluation analytics');

      // Extract query parameters
      const {
        startDate,
        endDate,
        challengeId,
        groupBy,
        limit
      } = req.query;

      // Sanitize any incoming MongoDB IDs
      const sanitizedChallengeId = challengeId
        ? MongoSanitizer.validateObjectId(challengeId as string, 'challenge')
        : undefined;

      // Log the analytics request
      this.logAction('get-ai-evaluation-analytics', req.user!.userId, {
        filters: {
          startDate,
          endDate,
          challengeId: sanitizedChallengeId,
          groupBy,
          limit
        },
        requestedAt: new Date().toISOString()
      });

      // Performance tracking
      const startTime = Date.now();

      // Validate groupBy value
      const allowedGroupBy = ['day', 'week', 'month'];
      const groupByValue =
        typeof groupBy === 'string' && allowedGroupBy.includes(groupBy)
          ? (groupBy as 'day' | 'week' | 'month')
          : undefined;

      // Get analytics via service
      const analytics = await this.aiEvaluationService.getEvaluationAnalytics({
        startDate: startDate ? new Date(startDate as string) : undefined,
        endDate: endDate ? new Date(endDate as string) : undefined,
        challengeId: sanitizedChallengeId,
        groupBy: groupByValue,
        limit: limit ? parseInt(limit as string, 10) : undefined
      });

      // Log performance metrics
      const processingTime = Date.now() - startTime;
      logger.debug('AI evaluation analytics request processing time', {
        processingTimeMs: processingTime,
        userId: req.user!.userId
      });

      this.sendSuccess(
        res,
        analytics,
        'AI evaluation analytics retrieved successfully'
      );
    }
  );

  /**
   * Retry a failed evaluation
   * @route POST /api/ai-evaluation/solutions/:solutionId/retry
   * @access Private - Admin or Architect only
   */
  public retryEvaluation = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'retrying AI evaluations');

      const { solutionId } = req.params;
      const { forceRestart, priority, skipSteps } = req.body;

      // Validate ObjectId format
      MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Log the retry request
      this.logAction('retry-ai-evaluation', req.user!.userId, {
        solutionId,
        forceRestart,
        priority,
        skipSteps,
        requestedAt: new Date().toISOString()
      });

      // Performance tracking
      const startTime = Date.now();

      // Start the retry process
      const evaluation = await this.aiEvaluationService.retryEvaluation(
        solutionId,
        {
          forceRestart,
          priority,
          skipSteps
        },
        req.user!.userId
      );

      // Log performance metrics
      const processingTime = Date.now() - startTime;
      logger.debug('AI evaluation retry request processing time', {
        solutionId,
        processingTimeMs: processingTime
      });

      this.sendSuccess(
        res,
        evaluation,
        'AI evaluation retry initiated successfully'
      );
    }
  );

  /**
   * Run the evaluation pipeline for a solution
   * Uses the standardized pipeline controller
   * @route POST /api/ai-evaluation/solutions/:solutionId/run-pipeline
   * @access Private - Admin or Architect only
   */
  public runEvaluationPipeline = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'running AI evaluation pipeline');

      const { solutionId } = req.params;

      // Validate ObjectId format
      MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Log the pipeline request
      this.logAction('run-ai-pipeline', req.user!.userId, {
        solutionId,
        requestedAt: new Date().toISOString()
      });

      // Start the evaluation process via service
      const result = await this.aiEvaluationService.runEvaluationPipeline(solutionId);

      this.sendSuccess(
        res,
        result,
        'AI evaluation pipeline executed successfully'
      );
    }
  );

  /**
   * Process all solutions for a challenge
   * @route POST /api/ai-evaluation/challenges/:challengeId/process
   * @access Private - Admin or Architect only
   */
  public processChallengeEvaluations = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify authorization
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.ARCHITECT], 'processing challenge evaluations');

      const { challengeId } = req.params;

      // Validate ObjectId format
      MongoSanitizer.validateObjectId(challengeId, 'challenge');

      // Log the evaluation request
      this.logAction('process-challenge-evaluations', req.user!.userId, {
        challengeId,
        requestedAt: new Date().toISOString()
      });

      // Process all challenge solutions
      const result = await this.aiEvaluationService.processEvaluationsForChallenge(challengeId);

      this.sendSuccess(
        res,
        result,
        `Successfully processed ${result.processed} out of ${result.totalSolutions} solutions`
      );
    }
  );
}

// Export singleton instance for use in routes
export const aiEvaluationController = new AIEvaluationController();