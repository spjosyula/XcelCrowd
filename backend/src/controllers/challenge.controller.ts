import { Response, NextFunction } from 'express';
import { UserRole, ChallengeStatus } from '../models/interfaces';
import { ChallengeService, challengeService } from '../services/challenge.service';
import { ProfileService, profileService } from '../services/profile.service';
import { ApiError } from '../utils/api.error';
import { catchAsync } from '../utils/catch.async';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { HTTP_STATUS } from '../constants';
import { validateObjectId } from '../utils/mongoUtils';
import { logger } from '../utils/logger';

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
   * Create a new challenge
   * @route POST /api/challenges
   * @access Private - Company only
   */
  createChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Authorize: Company role only
      this.verifyAuthorization(req, [UserRole.COMPANY], 'creating a challenge');

      // Get company profile ID
      const companyId = await this.getUserProfileId(req, UserRole.COMPANY);

      // Create challenge via service
      const challenge = await this.challengeService.createChallenge(companyId, req.body) as { _id: { toString(): string }, title: string, status: string };

      this.logAction('challenge-create', req.user!.userId, {
        challengeId: challenge._id.toString(),
        companyId,
        title: challenge.title,
        status: challenge.status
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `publish a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'publish'
      );

      // Verify business rules
      if (challenge.status !== ChallengeStatus.DRAFT) {
        throw ApiError.badRequest(
          `Cannot publish a challenge that is ${challenge.status}. Only draft challenges can be published.`,
          'INVALID_CHALLENGE_STATUS'
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : challenge.company.toString();

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
      const userRole = req.user!.role as UserRole;
      
      // Get student profile for visibility filters if applicable
      let studentProfile = null;
      if (userRole === UserRole.STUDENT && req.user?.userId) {
        try {
          studentProfile = await this.profileService.getStudentProfileByUserId(req.user.userId);
        } catch (error) {
          // Continue with null profile (public visibility only)
          logger.warn('[getAllChallenges] Student profile not found', {
            userId: req.user.userId,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }

      // Parse pagination parameters
      const page = req.query.page ? parseInt(req.query.page as string) : 1;
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;

      // Use service with user context for proper visibility filtering
      const result = await this.challengeService.getChallengesForUser(
        {
          status: status === '' ? 'all' :
            (status && Object.values(ChallengeStatus).includes(status as ChallengeStatus) ?
              status as ChallengeStatus : undefined),
          difficulty: difficulty as string,
          category: category as string | string[],
          searchTerm: searchTerm as string,
          page,
          limit
        }, 
        req.user?.userId, 
        userRole, 
        studentProfile
      );

      this.logAction('challenges-list', req.user!.userId, {
        count: result.data.length,
        total: result.total,
        filters: { status, difficulty, category, searchTerm }
      });

      this.sendPaginatedSuccess(
        res,
        {
          data: result.data,
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
      validateObjectId(id, 'challenge');

      // Get user role and profile information for visibility checks
      const userRole = req.user!.role as UserRole;
      const profileId = req.user?.profile?.toString();
      
      // Get student profile if applicable
      let studentProfile = null;
      if (userRole === UserRole.STUDENT) {
        try {
          studentProfile = await this.profileService.getStudentProfileByUserId(req.user!.userId);
        } catch (error) {
          logger.warn('[getChallengeById] Student profile not found', {
            userId: req.user!.userId,
            challengeId: id,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }

      // Use service to get challenge with visibility controls
      const challenge = await this.challengeService.getChallengeByIdWithVisibility(
        id,
        userRole,
        profileId,
        studentProfile
      );

      if (!challenge) {
        throw ApiError.notFound(
          `Challenge not found with id: ${id}`,
          'CHALLENGE_NOT_FOUND'
        );
      }

      this.logAction('challenge-view', req.user!.userId, {
        challengeId: id,
        challengeTitle: challenge.title,
        visibility: challenge.visibility || 'public'
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `update a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'update'
      );

      // Get company profile ID for company user
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : challenge.company.toString();

      // Update via service
      const updatedChallenge = await this.challengeService.updateChallenge(id, companyId, req.body);

      this.logAction('challenge-update', req.user!.userId, { 
        challengeId: id,
        updatedFields: Object.keys(req.body)
      });
      
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `delete a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'delete'
      );

      // Validate if challenge can be deleted based on business rules
      await this.challengeService.validateChallengeCanBeDeleted(id);

      // Delete via service
      await this.challengeService.deleteChallenge(id);

      this.logAction('challenge-delete', req.user!.userId, { 
        challengeId: id, 
        status: challenge.status,
        title: challenge.title
      });
      
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `close a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'close'
      );

      // Verify business rules
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw ApiError.badRequest(
          `Cannot close a challenge that is ${challenge.status}`,
          'INVALID_CHALLENGE_STATUS'
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : challenge.company.toString();

      // Close via service
      const updatedChallenge = await this.challengeService.closeChallenge(id, companyId);

      this.logAction('challenge-close', req.user!.userId, { 
        challengeId: id,
        previousStatus: challenge.status,
        newStatus: ChallengeStatus.CLOSED
      });
      
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `complete a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'complete'
      );

      // Verify business rules
      if (challenge.status !== ChallengeStatus.CLOSED) {
        throw ApiError.badRequest(
          `Cannot complete a challenge that is ${challenge.status}. Challenge must be closed first.`,
          'INVALID_CHALLENGE_STATUS'
        );
      }

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : challenge.company.toString();

      // Complete via service
      const updatedChallenge = await this.challengeService.completeChallenge(id, companyId);

      this.logAction('challenge-complete', req.user!.userId, { 
        challengeId: id,
        previousStatus: challenge.status,
        newStatus: ChallengeStatus.COMPLETED
      });
      
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
      // Verify user has company role
      this.verifyAuthorization(req, [UserRole.COMPANY], 'viewing company challenges');

      const companyId = await this.getUserProfileId(req, UserRole.COMPANY);
      
      // Parse query parameters
      const status = req.query.status && 
        Object.values(ChallengeStatus).includes(req.query.status as ChallengeStatus) ? 
        req.query.status as ChallengeStatus : undefined;
      
      const page = req.query.page ? parseInt(req.query.page as string) : 1;
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;

      // Get challenges via service
      const result = await this.challengeService.getChallenges({
        companyId,
        status,
        page,
        limit
      });

      this.logAction('company-challenges-list', req.user!.userId, {
        companyId,
        count: result.data.length,
        total: result.total
      });

      this.sendPaginatedSuccess(
        res,
        {
          data: result.data,
          total: result.total,
          page: result.page,
          limit: result.limit,
          totalPages: Math.ceil(result.total / result.limit),
          hasNextPage: result.page * result.limit < result.total,
          hasPrevPage: result.page > 1
        },
        'Company challenges retrieved successfully'
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

      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `view statistics for a challenge`);

      // Get company profile ID for authorization
      const profileId = req.user!.role === UserRole.COMPANY ? 
        await this.getUserProfileId(req, UserRole.COMPANY) : req.user!.userId;

      // Authorize challenge owner using service
      const challenge = await this.challengeService.authorizeChallengeOwner(
        profileId,
        req.user!.role as UserRole,
        id,
        'view statistics for'
      );

      // Get company profile ID
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : 'admin';

      // Get statistics via service
      const statistics = await this.challengeService.getChallengeStatistics(id, companyId);

      this.logAction('challenge-statistics', req.user!.userId, { 
        challengeId: id,
        challengeTitle: challenge.title
      });
      
      this.sendSuccess(res, statistics, 'Challenge statistics retrieved successfully');
    }
  );
}

// Export singleton instance for use in routes
export const challengeController = new ChallengeController();