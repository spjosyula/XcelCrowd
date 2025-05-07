import { Response, NextFunction } from 'express';
import { architectService, ArchitectService } from '../services/architect.service';
import { ChallengeStatus, HTTP_STATUS, UserRole, SolutionStatus } from '../models/interfaces';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catch.async';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/api.error';
import { Types } from 'mongoose';
import { dashboardService } from '../services/dashboard.service';


/********
 * Controller for architect-related operations
 * Extends BaseController for standardized response handling
 * Contains no business logic - delegates to ArchitectService
 */
export class ArchitectController extends BaseController {
  private readonly architectService: ArchitectService;
  constructor() {
    super();
    this.architectService = architectService;
  }

  /**
 * Create a new architect user (admin only)
 * @route POST /api/admin/architects
 * @access Private - Admin only
 */
  public createArchitectUser = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify admin authorization
      this.verifyAuthorization(req, [UserRole.ADMIN]);

      // Create architect via service
      const result = await this.architectService.createArchitectUser(
        req.user!.userId,
        req.body
      );

      // Prepare sanitized response (remove sensitive data)
      const sanitizedResponse = {
        user: {
          _id: result.user._id,
          email: result.user.email,
          role: result.user.role,
        },
        profile: result.profile
      };

      // Log the action
      this.logAction('create-architect-user', req.user!.userId, {
        architectId: result.user._id.toString()
      });

      // Send success response
      this.sendSuccess(
        res,
        sanitizedResponse,
        'Architect user created successfully',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Get architect profile
   * @route GET /architect/profile
   */
  public getProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role (authorization check)
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);

      // Delegate to service
      const profile = await this.architectService.getProfileByUserId(req.user!.userId);

      // Log and respond
      this.logAction('get-profile', req.user!.userId, { profileId: profile?._id });
      this.sendSuccess(res, profile, 'Architect profile retrieved successfully');
    }
  );

  /**
   * Create or update architect profile
   * @route PUT /architect/profile
   */
  public updateProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role (authorization check)
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
  
      // Sanitize and validate input data
      const validProfileFields = [
        'firstName', 'lastName', 'biography', 'specialization', 
        'skills', 'yearsOfExperience', 'contactEmail', 'profilePicture'
      ];
      
      const sanitizedProfileData = Object.keys(req.body)
        .filter(key => validProfileFields.includes(key))
        .reduce((obj: Record<string, any>, key) => {
          obj[key] = req.body[key];
          return obj;
        }, {});
  
      // Delegate validation and update to service with sanitized data
      const updatedProfile = await this.architectService.createOrUpdateProfile(
        req.user!.userId,
        sanitizedProfileData
      );
  
      // Log and respond
      this.logAction('update-profile', req.user!.userId, {
        updatedFields: Object.keys(sanitizedProfileData).join(', ')
      });
      
      this.sendSuccess(
        res,
        updatedProfile,
        'Architect profile updated successfully'
      );
    }
  );

  /**
   * Get pending solutions for review
   * @route GET /architect/solutions
   */
  public getPendingSolutions = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Use BaseController authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'viewing pending solutions');

      // Sanitize and validate query parameters
      const sanitizedQuery = {
        status: typeof req.query.status === 'string' ? req.query.status : undefined,
        page: req.query.page ? Math.max(1, parseInt(String(req.query.page))) : 1,
        limit: req.query.limit ? Math.min(100, Math.max(1, parseInt(String(req.query.limit)))) : 10,
        sortBy: typeof req.query.sortBy === 'string' ? req.query.sortBy : 'createdAt',
        sortOrder: req.query.sortOrder === 'asc' ? 'asc' : 'desc',
        challengeId: typeof req.query.challengeId === 'string' && req.query.challengeId ? req.query.challengeId : undefined
      };
      
      // Validate status parameter if provided
      if (sanitizedQuery.status && 
          !Object.values(SolutionStatus).includes(sanitizedQuery.status as SolutionStatus)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid status parameter. Must be one of: ${Object.values(SolutionStatus).join(', ')}`,
          true,
          'INVALID_STATUS_PARAM'
        );
      }

      // Validate sortBy against allowed fields
      const allowedSortFields = ['createdAt', 'updatedAt', 'title', 'submittedAt'];
      if (sanitizedQuery.sortBy && !allowedSortFields.includes(sanitizedQuery.sortBy)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid sortBy parameter. Must be one of: ${allowedSortFields.join(', ')}`,
          true,
          'INVALID_SORT_FIELD'
        );
      }
      
      // Validate challengeId if provided
      if (sanitizedQuery.challengeId && !Types.ObjectId.isValid(sanitizedQuery.challengeId)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid challenge ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }
      
      // Log request parameters for debugging
      logger.debug('Getting pending solutions with params:', {
        userId: req.user!.userId,
        query: sanitizedQuery
      });

      // Get solutions via service - cast status to SolutionStatus enum type
      const result = await this.architectService.getPendingSolutions({
        status: sanitizedQuery.status as SolutionStatus | undefined,
        page: sanitizedQuery.page,
        limit: sanitizedQuery.limit,
        challengeId: sanitizedQuery.challengeId
      });

      // Log the action
      this.logAction('view-pending-solutions', req.user!.userId, {
        filterCount: Object.keys(sanitizedQuery).filter(k => 
          sanitizedQuery[k as keyof typeof sanitizedQuery] !== undefined).length,
        status: sanitizedQuery.status,
        challengeId: sanitizedQuery.challengeId
      });

      // Respond with paginated result - transform to expected PaginationResult format
      this.sendPaginatedSuccess(
        res,
        {
          data: result.solutions,
          total: result.total,
          page: result.page,
          limit: result.limit,
          totalPages: Math.ceil(result.total / result.limit),
          hasNextPage: result.page * result.limit < result.total,
          hasPrevPage: result.page > 1
        },
        'Pending solutions retrieved successfully',
      );
    }
  );

  /**
   * Get a specific solution by ID
   * @route GET /architect/solutions/:id
   */
  public getSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Use BaseController authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'viewing solution details');

      const { id } = req.params;
      
      // Validate solution ID format
      if (!id || !Types.ObjectId.isValid(id)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid solution ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }

      // Log request details
      logger.debug('Getting solution details', {
        userId: req.user!.userId,
        solutionId: id
      });

      // Get solution via service
      const solution = await this.architectService.getSolutionById(id);

      // Validate response
      if (!solution) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Solution not found',
          true,
          'SOLUTION_NOT_FOUND'
        );
      }

      // Log the action
      this.logAction('view-solution-details', req.user!.userId, {
        solutionId: id,
        challengeId: typeof solution.challenge === 'string' 
          ? solution.challenge 
          : solution.challenge?._id?.toString()
      });

      // Respond
      this.sendSuccess(res, solution, 'Solution retrieved successfully');
    }
  );

  /**
   * Review a solution
   * @route POST /architect/solutions/:id/review
   */
  public reviewSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'reviewing solutions');

      const { id } = req.params;
      
      // Validate solution ID format
      if (!id || !Types.ObjectId.isValid(id)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid solution ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }

      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);

      // Validate required fields
      const { status, feedback } = req.body;
      if (!status) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Status is required for solution review',
          true,
          'MISSING_REQUIRED_FIELD'
        );
      }

      // Validate status value
      if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(status)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid status. Must be either ${SolutionStatus.APPROVED} or ${SolutionStatus.REJECTED}`,
          true,
          'INVALID_STATUS_VALUE'
        );
      }

      // Validate feedback
      if (!feedback || typeof feedback !== 'string' || feedback.trim().length === 0) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Feedback is required and must be non-empty',
          true,
          'INVALID_FEEDBACK'
        );
      }

      // Score validation for approved solutions
      let score = req.body.score;
      if (status === SolutionStatus.APPROVED) {
        if (score === undefined || score === null) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Score is required for approved solutions',
            true,
            'MISSING_SCORE'
          );
        }
        
        score = Number(score);
        if (isNaN(score) || score < 1 || score > 10 || !Number.isInteger(score)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Score must be an integer between 1 and 10 for approved solutions',
            true,
            'INVALID_SCORE_VALUE'
          );
        }
      }
      
      // Log review attempt for audit purposes
      logger.debug('Attempting to review solution', {
        userId: req.user!.userId,
        architectId,
        solutionId: id,
        status
      });

      // Submit review via service with validated data
      const updatedSolution = await this.architectService.reviewSolution(
        id,
        architectId,
        { 
          status, 
          feedback, 
          score: status === SolutionStatus.APPROVED ? score : undefined 
        }
      );

      // Log and respond
      this.logAction('review-solution', req.user!.userId, {
        solutionId: id,
        status,
        architectId
      });

      this.sendSuccess(
        res,
        updatedSolution,
        `Solution ${status === SolutionStatus.APPROVED ? 'approved' : 'rejected'} successfully`
      );
    }
  );

  /**
 * Claim a solution for review
 * @route PATCH /api/solutions/:id/claim
 * @access Private - Architect only
 * @deprecated Use challenge claiming instead
 */
  public claimSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'claiming solutions for review');
  
      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);
      
      const { id } = req.params;
  
      // Business logic moved to service - but ensure we pass the architectId
      const updatedSolution = await this.architectService.claimSolutionViaChallenge(
        architectId,  // Use architectId instead of userId for better security
        id
      );
  
      // Log action and send response
      this.logAction('claim-solution-via-challenge', req.user!.userId, {
        solutionId: id,
        architectId, // Add architectId to log
        challengeId: typeof updatedSolution.challenge === 'string'
          ? updatedSolution.challenge
          : updatedSolution.challenge?._id?.toString()
      });
  
      this.sendSuccess(
        res,
        updatedSolution,
        'Solution claimed for review successfully by claiming its parent challenge'
      );
    }
  );

  /**
 * Claim a challenge for review
 * @route POST /api/architect/challenges/:challengeId/claim
 * @access Private - Architect only
 */
  public claimChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify architect authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'claiming challenges for review');

      const { challengeId } = req.params;

      // Business logic moved to service
      const challenge = await this.architectService.claimChallengeById(
        req.user!.userId,
        challengeId
      );

      // Log the action for audit trail
      this.logAction('claim-challenge', req.user!.userId, {
        challengeId,
        challengeTitle: challenge.title
      });

      // Return success response
      this.sendSuccess(
        res,
        challenge,
        'Challenge claimed successfully. All associated solutions are now assigned to you for review.',
        HTTP_STATUS.OK
      );
    }
  );

  /**
 * Get pending challenges available for review
 * @route GET /api/architect/challenges
 * @access Private - Architect only
 */
  public getPendingChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify architect authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'viewing pending challenges');

      // Sanitize and validate query parameters
      const sanitizedQuery = {
        status: typeof req.query.status === 'string' ? req.query.status : undefined,
        page: req.query.page ? Math.max(1, parseInt(String(req.query.page))) : 1,
        limit: req.query.limit ? Math.min(100, Math.max(1, parseInt(String(req.query.limit)))) : 10,
        sortBy: typeof req.query.sortBy === 'string' ? req.query.sortBy : 'createdAt',
        sortOrder: req.query.sortOrder === 'asc' ? 'asc' : 'desc'
      };
      
      // Validate status parameter if provided
      if (sanitizedQuery.status && 
          !Object.values(ChallengeStatus).includes(sanitizedQuery.status as ChallengeStatus)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid status parameter. Must be one of: ${Object.values(ChallengeStatus).join(', ')}`,
          true,
          'INVALID_STATUS_PARAM'
        );
      }

      // Validate sortBy against allowed fields
      const allowedSortFields = ['createdAt', 'updatedAt', 'title', 'deadline', 'difficulty'];
      if (sanitizedQuery.sortBy && !allowedSortFields.includes(sanitizedQuery.sortBy)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid sortBy parameter. Must be one of: ${allowedSortFields.join(', ')}`,
          true,
          'INVALID_SORT_FIELD'
        );
      }
      
      // Log request parameters for debugging
      logger.debug('Getting pending challenges with params:', {
        userId: req.user!.userId,
        query: sanitizedQuery
      });

      // Delegate to service layer with sanitized parameters
      const result = await this.architectService.getPendingChallenges(
        req.user!.userId,
        sanitizedQuery
      );

      // Log the action
      this.logAction('get-pending-challenges', req.user!.userId, {
        count: result.challenges?.length || 0,
        filter: sanitizedQuery.status || 'all'
      });

      // Send paginated success response
      this.sendPaginatedSuccess(
        res,
        {
          data: result.challenges || [],
          total: result.total || 0,
          page: result.page || 1,
          limit: result.limit || 10,
          totalPages: Math.ceil((result.total || 0) / (result.limit || 10)),
          hasNextPage: (result.page || 1) * (result.limit || 10) < (result.total || 0),
          hasPrevPage: (result.page || 1) > 1
        },
        'Pending challenges retrieved successfully'
      );
    }
  );

  /**
   * Get all challenges claimed by the architect
   * @route GET /api/architect/challenges/claimed
   * @access Private - Architect only
   */
  public getClaimedChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify architect authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'viewing claimed challenges');

      // Sanitize and validate query parameters
      const sanitizedQuery = {
        status: typeof req.query.status === 'string' ? req.query.status : undefined,
        page: req.query.page ? Math.max(1, parseInt(String(req.query.page))) : 1,
        limit: req.query.limit ? Math.min(100, Math.max(1, parseInt(String(req.query.limit)))) : 10,
        sortBy: typeof req.query.sortBy === 'string' ? req.query.sortBy : 'createdAt',
        sortOrder: req.query.sortOrder === 'asc' ? 'asc' : 'desc'
      };
      
      // Validate status parameter if provided
      if (sanitizedQuery.status && 
          !Object.values(ChallengeStatus).includes(sanitizedQuery.status as ChallengeStatus)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid status parameter. Must be one of: ${Object.values(ChallengeStatus).join(', ')}`,
          true,
          'INVALID_STATUS_PARAM'
        );
      }

      // Validate sortBy against allowed fields
      const allowedSortFields = ['createdAt', 'updatedAt', 'title', 'deadline', 'claimedAt'];
      if (sanitizedQuery.sortBy && !allowedSortFields.includes(sanitizedQuery.sortBy)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid sortBy parameter. Must be one of: ${allowedSortFields.join(', ')}`,
          true,
          'INVALID_SORT_FIELD'
        );
      }
      
      // Log request parameters for debugging
      logger.debug('Getting claimed challenges with params:', {
        userId: req.user!.userId,
        query: sanitizedQuery
      });

      // Delegate to service layer with sanitized parameters
      const result = await this.architectService.getArchitectClaimedChallenges(
        req.user!.userId,
        sanitizedQuery
      );

      // Validate result structure
      if (!result || typeof result !== 'object' || !Array.isArray(result.challenges)) {
        logger.error('Invalid result structure from getArchitectClaimedChallenges', {
          userId: req.user!.userId,
          resultType: typeof result
        });
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Invalid data structure returned from service',
          true,
          'INVALID_SERVICE_RESPONSE'
        );
      }

      // Log the action
      this.logAction('get-claimed-challenges', req.user!.userId, {
        count: result.challenges.length,
        filter: sanitizedQuery.status || 'all'
      });

      // Send paginated success response
      this.sendPaginatedSuccess(
        res,
        {
          data: result.challenges,
          total: result.total,
          page: result.page,
          limit: result.limit,
          totalPages: Math.ceil(result.total / result.limit),
          hasNextPage: result.page * result.limit < result.total,
          hasPrevPage: result.page > 1
        },
        'Claimed challenges retrieved successfully'
      );
    }
  );

  /**
   * Get architect dashboard statistics
   * @route GET /architect/dashboard
   */
  public getDashboardStats = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Use BaseController authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'accessing dashboard statistics');

      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);

      // Pass the architectId to ensure proper authorization
      const stats = await this.architectService.getDashboardStats(architectId);

      // Log the action
      this.logAction('view-dashboard-stats', req.user!.userId, {
        profileId: architectId // Add profile ID to the log for audit trails
      });

      // Respond
      this.sendSuccess(res, stats, 'Dashboard statistics retrieved successfully');
    }
  );

  /**
   * Select approved solutions to forward to the company
   * @route POST /architect/challenges/:challengeId/select-solutions
   */
  public selectSolutionsForCompany = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Use BaseController authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'selecting solutions for company');
      
      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);

      // Validate challengeId format
      const { challengeId } = req.params;
      if (!challengeId || !Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid challenge ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }

      // Add limit to prevent performance issues with large arrays
      if (!Array.isArray(req.body.solutionIds)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Solution IDs must be provided as an array',
          true,
          'INVALID_SOLUTION_IDS'
        );
      }

      if (req.body.solutionIds.length > 100) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Too many solutions selected (maximum 100)',
          true,
          'EXCESSIVE_SELECTION'
        );
      }

      // Validate each solution ID in the array
      for (const solutionId of req.body.solutionIds) {
        if (!Types.ObjectId.isValid(solutionId)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid solution ID format: ${solutionId}`,
            true,
            'INVALID_SOLUTION_ID'
          );
        }
      }

      // Log details of the request for audit/debugging
      logger.debug('Selecting solutions for company', {
        userId: req.user!.userId,
        architectId,
        challengeId,
        solutionCount: req.body.solutionIds.length
      });

      // Process selection via service with added performance metrics
      const startTime = Date.now();
      const selectedSolutions = await this.architectService.selectSolutionsForCompany(
        challengeId,
        req.body.solutionIds,
        architectId
      );
      const processingTime = Date.now() - startTime;

      // Log action with performance metrics
      this.logAction('select-solutions', req.user!.userId, {
        challengeId,
        solutionCount: req.body.solutionIds.length,
        processingTimeMs: processingTime
      });

      this.sendSuccess(
        res,
        selectedSolutions,
        'Solutions have been successfully selected for the company'
      );
    }
  );

  /**
   * Get comprehensive dashboard metrics for architect
   * @route GET /api/architect/dashboard/metrics
   * @access Private - Architect only
   */
  public getDashboardMetrics = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify architect authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'accessing dashboard metrics');
      
      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);
      
      // Get dashboard metrics from service
      const metrics = await dashboardService.getArchitectDashboardMetrics(architectId);
      
      // Log the action
      this.logAction('view-dashboard-metrics', req.user!.userId, {
        architectId
      });
      
      // Send response
      this.sendSuccess(
        res,
        metrics,
        'Dashboard metrics retrieved successfully'
      );
    }
  );
  
  /**
   * Get detailed solution analytics with AI evaluation details
   * @route GET /api/architect/solutions/:id/analytics
   * @access Private - Architect only
   */
  public getSolutionAnalytics = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify architect authorization
      this.verifyAuthorization(req, [UserRole.ARCHITECT], 'viewing solution analytics');
      
      const { id } = req.params;
      
      // Validate solution ID format
      if (!id || !Types.ObjectId.isValid(id)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid solution ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }
      
      // Get solution analytics from dashboard service
      const analytics = await dashboardService.getSolutionAnalytics(id);
      
      // Log the action
      this.logAction('view-solution-analytics', req.user!.userId, {
        solutionId: id
      });
      
      // Send response
      this.sendSuccess(
        res,
        analytics,
        'Solution analytics retrieved successfully'
      );
    }
  );
}

// Export singleton instance for consistency across routes
export const architectController = new ArchitectController();