import { Response, NextFunction } from 'express';
import { UserRole, ChallengeStatus } from '../models/interfaces';
import { ChallengeService, challengeService } from '../services/challenge.service';
import { ProfileService, profileService } from '../services/profile.service';
import { ApiError } from '../utils/api.error';
import { catchAsync } from '../utils/catch.async';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { HTTP_STATUS } from '../constants';

/**
 * Controller for challenge-related operations
 * Extends BaseController for standardized response handling
 */
export class ChallengeController extends BaseController {
  private readonly challengeService: ChallengeService;
  private readonly profileService: ProfileService;

  constructor() {
    super();
    this.challengeService = challengeService;
    this.profileService = profileService;
  }

  /**
  * Helper method for common challenge owner authorization
  */
  private async authorizeChallengeOwner(
    req: AuthRequest,
    challengeId: string,
    action: string
  ) {
    // Verify user has appropriate role
    this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN]);

    // Validate challenge ID
    this.validateObjectId(challengeId, 'challenge');

    // Get the challenge
    const challenge = await this.challengeService.getChallengeById(challengeId);

    // Verify ownership (except for admin)
    await this.authorize(req, {
      allowedRoles: [UserRole.COMPANY, UserRole.ADMIN],
      resource: challenge,
      ownerIdField: 'company',
      ownerRole: UserRole.COMPANY,
      failureMessage: `You do not have permission to ${action} this challenge`
    });

    return challenge;
  }

  /**
   * Create a new challenge
   * @route POST /api/challenges
   * @access Private - Company only
   */
  createChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Authorize: Company role only
      this.verifyAuthorization(req, [UserRole.COMPANY]);

      // Get company profile ID
      const companyId = await this.getUserProfileId(req, UserRole.COMPANY);

      // Determine initial status based on autoPublish flag
      const initialStatus = req.body.autoPublish === true ?
        ChallengeStatus.ACTIVE : ChallengeStatus.DRAFT;

      // Create challenge via service with explicit status
      const challengeData = {
        ...req.body,
        status: initialStatus
      };
      delete challengeData.autoPublish; // Remove the flag before saving

      const challenge = await this.challengeService.createChallenge(companyId, challengeData) as { _id: string };

      this.logAction('challenge-create', req.user!.userId, {
        challengeId: challenge._id.toString(),
        status: initialStatus
      });

      this.sendSuccess(
        res,
        challenge,
        'Challenge created successfully',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
 * Publish a challenge (transition from DRAFT to ACTIVE)
 * @route PATCH /api/challenges/:id/publish
 * @access Private - Challenge owner (Company) or Admin only
 */
  publishChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      const challenge = await this.authorizeChallengeOwner(req, id, 'publish');

      // Verify business rules
      if (challenge.status !== ChallengeStatus.DRAFT) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot publish a challenge that is ${challenge.status}. Only draft challenges can be published.`
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        await this.getUserProfileId(req, UserRole.COMPANY) : challenge.company.toString();

      // Publish via service
      const updatedChallenge = await this.challengeService.publishChallenge(id, companyId);

      this.logAction('challenge-publish', req.user!.userId, {
        challengeId: id,
        previousStatus: challenge.status,
        newStatus: ChallengeStatus.ACTIVE
      });

      this.sendSuccess(res, updatedChallenge, 'Challenge published successfully');
    }
  );

  /**
   * Get all challenges 
   * @route GET /api/challenges
   * @access Private - Authenticated users only (Student, Company, Admin)
   */
  getAllChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user is authenticated
      this.verifyAuthorization(req);

      const { status, difficulty, category, searchTerm } = req.query;

      // Get student profile for visibility filters if applicable
      let studentProfile = null;
      const userRole = req.user!.role as UserRole;
      if (userRole === UserRole.STUDENT && req.user?.userId) {
        try {
          studentProfile = await this.profileService.getStudentProfileByUserId(req.user.userId);
        } catch (error) {
          // If profile can't be found, continue without it (public visibility only)
        }
      }

      // Use service with user context for proper visibility filtering
      const result = await this.challengeService.getChallengesForUser({
        status: status === '' ? 'all' :
          (status && Object.values(ChallengeStatus).includes(status as ChallengeStatus) ?
            status as ChallengeStatus : undefined),
        difficulty: difficulty as string,
        category: category as string | string[],
        searchTerm: searchTerm as string,
        page: req.query.page ? parseInt(req.query.page as string) : 1,
        limit: req.query.limit ? parseInt(req.query.limit as string) : 10
      }, req.user?.userId, userRole, studentProfile);

      this.logAction('challenges-list', req.user!.userId, {
        count: result.challenges.length,
        filters: { status, difficulty, category }
      });

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
        'Challenges retrieved successfully'
      );
    }
  );

  /**
   * Get challenge by ID
   * @route GET /api/challenges/:id
   * @access Private - Authenticated users only (Student, Company, Admin)
   */
  getChallengeById = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user is authenticated
      this.verifyAuthorization(req);

      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      // Get user role and profile information for visibility checks
      const userRole = req.user!.role as UserRole;
      const profileId = req.user?.profile?.toString();
      let studentProfile = null;

      if (userRole === UserRole.STUDENT) {
        studentProfile = await this.profileService.getStudentProfileByUserId(req.user!.userId);
      }

      // Use service to get challenge with visibility controls
      const challenge = await this.challengeService.getChallengeByIdWithVisibility(
        id,
        userRole,
        profileId,
        studentProfile
      );

      this.logAction('challenge-view', req.user!.userId, {
        challengeId: id,
        anonymous: challenge.visibility === 'anonymous'
      });

      this.sendSuccess(res, challenge, 'Challenge retrieved successfully');
    }
  );

  /**
   * Update challenge
   * @route PUT /api/challenges/:id
   * @access Private - Challenge owner (Company) or Admin only
   */
  updateChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      const challenge = await this.authorizeChallengeOwner(req, id, 'update');

      // Get company profile ID for company user
      const companyId = req.user!.role === UserRole.COMPANY ?
        await this.getUserProfileId(req, UserRole.COMPANY) : null;

      // Update via service
      const updatedChallenge = await this.challengeService.updateChallenge(
        id,
        companyId || challenge.company.toString(),
        req.body
      );

      this.logAction('challenge-update', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, updatedChallenge, 'Challenge updated successfully');
    }
  );

  /**
   * Delete challenge
   * @route DELETE /api/challenges/:id
   * @access Private - Challenge owner (Company) or Admin only
   */
  deleteChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      const challenge = await this.authorizeChallengeOwner(req, id, 'delete');

      // Validate if challenge can be deleted based on business rules
      await this.challengeService.validateChallengeCanBeDeleted(id);

      // Delete via service
      await this.challengeService.deleteChallenge(id);

      this.logAction('challenge-delete', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, null, 'Challenge deleted successfully');
    }
  );

  /**
   * Close challenge (mark as closed, no more submissions)
   * @route PATCH /api/challenges/:id/close
   * @access Private - Company only (owner)
   */
  closeChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      const challenge = await this.authorizeChallengeOwner(req, id, 'close');

      // Verify business rules
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot close a challenge that is ${challenge.status}`
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        await this.getUserProfileId(req, UserRole.COMPANY) : challenge.company.toString();

      // Close via service
      const updatedChallenge = await this.challengeService.closeChallenge(id, companyId);

      this.logAction('challenge-close', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, updatedChallenge, 'Challenge closed successfully');
    }
  );

  /**
   * Mark challenge as completed
   * @route PATCH /api/challenges/:id/complete
   * @access Private - Company only (owner)
   */
  completeChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      const challenge = await this.authorizeChallengeOwner(req, id, 'complete');

      // Verify business rules
      if (challenge.status !== ChallengeStatus.CLOSED) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot complete a challenge that is ${challenge.status}. Challenge must be closed first.`
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        await this.getUserProfileId(req, UserRole.COMPANY) : challenge.company.toString();

      // Complete via service
      const updatedChallenge = await this.challengeService.completeChallenge(id, companyId);

      this.logAction('challenge-complete', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, updatedChallenge, 'Challenge marked as completed successfully');
    }
  );

  /**
   * Get challenges created by the authenticated company
   * @route GET /api/company/challenges
   * @access Private - Company only
   */
  getCompanyChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has company role and get company profile ID
      const companyId = await this.getUserProfileId(req, UserRole.COMPANY);

      const { status, page, limit } = req.query;

      // Get challenges via service
      const result = await this.challengeService.getChallenges({
        companyId,
        status: status && Object.values(ChallengeStatus).includes(status as ChallengeStatus) ? status as ChallengeStatus : undefined,
        page: page ? parseInt(page as string) : 1,
        limit: limit ? parseInt(limit as string) : 10
      });

      this.logAction('company-challenges-list', req.user!.userId, {
        count: result.challenges.length,
        filters: { status }
      });

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
        'Challenges retrieved successfully'
      );
    }
  );

  /**
   * Get challenge statistics
   * @route GET /api/challenges/:id/statistics
   * @access Private - Challenge owner (Company) or Admin only
   */
  getChallengeStatistics = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { id } = req.params;

      // Use helper for standard owner authorization
      await this.authorizeChallengeOwner(req, id, 'view statistics for');

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        await this.getUserProfileId(req, UserRole.COMPANY) : null;

      // Get statistics via service
      const statistics = await this.challengeService.getChallengeStatistics(
        id,
        companyId || 'admin' // Handle admin case
      );

      this.logAction('challenge-statistics', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, statistics, 'Challenge statistics retrieved successfully');
    }
  );
}

// Export singleton instance for use in routes
export const challengeController = new ChallengeController();