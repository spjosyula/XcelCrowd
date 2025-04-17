import { Response, NextFunction } from 'express';
import { architectService, ArchitectService} from '../services/architect.service';
import { ChallengeStatus, HTTP_STATUS, UserRole } from '../models/interfaces';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catch.async';
import { logger } from '../utils/logger';


/**
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

      // Delegate validation and update to service
      const updatedProfile = await this.architectService.createOrUpdateProfile(
        req.user!.userId,
        req.body
      );

      // Log and respond
      this.logAction('update-profile', req.user!.userId);
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

      // Filter parsing and validation via service
      const filters = this.architectService.parseSolutionFilters(req.query);

      // Get solutions via service
      const result = await this.architectService.getPendingSolutions(filters);

      // Log the action
      this.logAction('view-pending-solutions', req.user!.userId, { 
        filterCount: Object.keys(filters).length 
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

      // Get solution via service (includes ID validation)
      const solution = await this.architectService.getSolutionById(req.params.id);

      // Log the action
      this.logAction('view-solution-details', req.user!.userId, { 
        solutionId: req.params.id 
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

      // Get architect profile ID
      const architectId = await this.getUserProfileId(req, UserRole.ARCHITECT);

      // Validate review data via service
      const reviewData = this.architectService.validateReviewData(req.body);

      // Submit review via service
      const updatedSolution = await this.architectService.reviewSolution(
        id,
        architectId,
        reviewData
      );

      // Log and respond
      this.logAction('review-solution', req.user!.userId, {
        solutionId: id,
        status: reviewData.status
      });

      this.sendSuccess(
        res,
        updatedSolution,
        'Solution reviewed successfully'
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

      // Business logic moved to service
      const updatedSolution = await this.architectService.claimSolutionViaChallenge(
        req.user!.userId,
        id
      );

      // Log action and send response
      this.logAction('claim-solution-via-challenge', req.user!.userId, {
        solutionId: id,
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
  
      // Log request parameters for debugging
      logger.debug('Getting pending challenges with params:', {
        userId: req.user!.userId,
        query: req.query
      });
  
      // Delegate to service layer
      const result = await this.architectService.getPendingChallenges(
        req.user!.userId,
        req.query
      );
  
      // Log the action
      this.logAction('get-pending-challenges', req.user!.userId, {
        count: result.challenges?.length || 0,
        filter: req.query.status || 'all'
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

      // Business logic moved to service
      const result = await this.architectService.getArchitectClaimedChallenges(
        req.user!.userId,
        req.query
      );

      // Log the action
      this.logAction('get-claimed-challenges', req.user!.userId, {
        count: result.challenges.length,
        filter: req.query.status || 'all'
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

      // Get stats via service
      const stats = await this.architectService.getDashboardStats(req.user!.userId);

      // Log the action
      this.logAction('view-dashboard-stats', req.user!.userId);

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

      // Validate input data via service
      const validatedSolutionIds = this.architectService.validateSolutionSelectionData(
        req.params.challengeId,
        req.body.solutionIds
      );

      // Process selection via service
      const selectedSolutions = await this.architectService.selectSolutionsForCompany(
        req.params.challengeId,
        validatedSolutionIds,
        architectId
      );

      // Log and respond
      this.logAction('select-solutions', req.user!.userId, {
        challengeId: req.params.challengeId,
        solutionCount: validatedSolutionIds.length
      });

      this.sendSuccess(
        res,
        selectedSolutions,
        'Solutions have been successfully selected for the company'
      );
    }
  );
}

// Export singleton instance for consistency across routes
export const architectController = new ArchitectController();