import { Response, NextFunction } from 'express';
import { UserRole, ChallengeStatus } from '../models/interfaces';
import { ChallengeService, challengeService } from '../services/challenge.service';
import { ProfileService, profileService } from '../services/profile.service';
import { ApiError } from '../utils/api.error';
import { catchAsync } from '../utils/catch.async';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { HTTP_STATUS } from '../constants';
import { MongoSanitizer } from '../utils/mongo.sanitize';
import { logger } from '../utils/logger';
import { Types } from 'mongoose';
import Challenge from '../models/Challenge';

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

      try {
        // Enhanced logging for debugging
        logger.debug('[publishChallenge] Starting challenge publication process', {
          challengeId: id,
          userId: req.user?.userId,
          userRole: req.user?.role,
          user: req.user
        });

        // Verify user has appropriate role
        this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN], `publish a challenge`);

        // Get company profile ID for authorization
        let profileId: string;
        
        if (req.user!.role === UserRole.COMPANY) {
          // For company users, get their company profile
          try {
            logger.debug('[publishChallenge] Fetching company profile for authorization', {
              userId: req.user!.userId
            });
            
            const companyProfile = await this.profileService.getCompanyProfileByUserId(req.user!.userId);
            
            logger.debug('[publishChallenge] Company profile retrieved', {
              userId: req.user!.userId,
              companyProfileId: companyProfile._id,
              companyName: companyProfile.companyName
            });
            
            profileId = (companyProfile._id as Types.ObjectId).toString();
          } catch (profileError) {
            logger.error('[publishChallenge] Failed to get company profile', {
              userId: req.user!.userId,
              error: profileError instanceof Error ? profileError.message : String(profileError),
              stack: profileError instanceof Error ? profileError.stack : undefined
            });
            throw ApiError.forbidden(
              'Unable to verify company profile',
              'COMPANY_PROFILE_NOT_FOUND'
            );
          }
        } else {
          // For admin users
          profileId = req.user!.userId;
        }

        logger.debug('[publishChallenge] Profile ID resolved for authorization', {
          profileId,
          userRole: req.user!.role
        });

        // Authorize challenge owner using service
        logger.debug('[publishChallenge] Authorizing challenge ownership', {
          challengeId: id,
          profileId,
          userRole: req.user!.role
        });
        
        const challenge = await this.challengeService.authorizeChallengeOwner(
          profileId,
          req.user!.role as UserRole,
          id,
          'publish'
        );
        
        logger.debug('[publishChallenge] Challenge ownership verified', {
          challengeId: id,
          challengeCompanyId: typeof challenge.company === 'object' ? challenge.company._id : challenge.company
        });

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
        logger.debug('[publishChallenge] Publishing challenge', {
          challengeId: id,
          companyId
        });
        
        const updatedChallenge = await this.challengeService.publishChallenge(id, companyId);

        logger.debug('[publishChallenge] Challenge successfully published', {
          challengeId: id,
          status: updatedChallenge.status
        });

        this.logAction('challenge-publish', req.user!.userId, {
          challengeId: id,
          previousStatus: challenge.status,
          newStatus: ChallengeStatus.ACTIVE
        });

        this.sendSuccess(res, updatedChallenge, 'Challenge published successfully');
      } catch (error) {
        // Log the error with context
        logger.error('[publishChallenge] Failed to publish challenge', {
          challengeId: id,
          userId: req.user?.userId,
          userRole: req.user?.role,
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        });
        
        // Let the middleware handle the error
        next(error);
      }
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
      MongoSanitizer.validateObjectId(id, 'challenge');

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
   * Complete a challenge with final selections
   * @route POST /api/challenges/:id/complete
   * @access Private - Company only
   */
  completeChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has company role
      this.verifyAuthorization(req, [UserRole.COMPANY]);

      const { id } = req.params;
      
      // Get company profile ID
      const companyId = await this.getUserProfileId(req, UserRole.COMPANY);

      // Log the request
      logger.info(`Completing challenge with final selections`, {
        challengeId: id,
        userId: req.user!.userId,
        companyId
      });

      // Mark challenge as completed and get the selected solutions
      const result = await this.challengeService.markChallengeAsCompleted(id, companyId);

      // Log the completion
      this.logAction('complete-challenge', req.user!.userId, {
        challengeId: id,
        companyId,
        selectedSolutions: result.selectedSolutions.length,
        challengeStatus: result.challenge.status
      });

      // Send success response
      this.sendSuccess(
        res,
        result,
        `Challenge completed successfully with ${result.selectedSolutions.length} winning solutions`,
        HTTP_STATUS.OK
      );
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

      // Get company profile ID - FIXED to match pattern used in other methods
      const companyId = req.user!.role === UserRole.COMPANY ?
        profileId : challenge.company.toString();

      // Get statistics via service
      const statistics = await this.challengeService.getChallengeStatistics(id, companyId);

      this.logAction('challenge-statistics', req.user!.userId, {
        challengeId: id,
        challengeTitle: challenge.title
      });

      this.sendSuccess(res, statistics, 'Challenge statistics retrieved successfully');
    }
  );

  /**
   * Process all solutions for a challenge and submit them to architect review
   * This endpoint is used when a challenge deadline is reached
   * @route POST /api/challenges/:id/process-for-review
   * @access Private - Admin, Company
   */
  processChallengeForReview = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has appropriate role
      this.verifyAuthorization(req, [UserRole.ADMIN, UserRole.COMPANY]);

      const { id } = req.params;

      // Log the request
      logger.info(`Processing challenge for architect review`, {
        challengeId: id,
        userId: req.user!.userId
      });

      // Get solution service to process the challenge
      const { solutionService } = await import('../services/solution.service');

      // Process challenge solutions
      const result = await solutionService.processChallengeForArchitectReview(id);

      // Log the completion
      this.logAction('process-challenge-for-review', req.user!.userId, {
        challengeId: id,
        processedSolutions: result.processedSolutions,
        total: result.totalSolutions
      });

      // Send success response
      this.sendSuccess(
        res,
        result,
        `Successfully processed ${result.processedSolutions} out of ${result.totalSolutions} solutions for architect review`,
        HTTP_STATUS.OK
      );
    }
  );

  /**
   * Diagnostic endpoint to check challenge ownership
   * NOT FOR PRODUCTION USE - Debugging only
   */
  checkChallengeOwnership = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      try {
        const { id } = req.params;
        
        logger.info('[checkChallengeOwnership] Diagnostic check started', {
          challengeId: id,
          userId: req.user?.userId,
          userRole: req.user?.role
        });
        
        // Verify user role
        if (req.user?.role !== UserRole.COMPANY && req.user?.role !== UserRole.ADMIN) {
          throw ApiError.forbidden('Only company and admin users can perform this check');
        }
        
        // Get challenge to check
        const challenge = await Challenge.findById(id);
        if (!challenge) {
          throw ApiError.notFound('Challenge not found');
        }
        
        // Get company profile information
        let profileId = null;
        let companyProfile = null;
        
        if (req.user?.role === UserRole.COMPANY) {
          try {
            companyProfile = await this.profileService.getCompanyProfileByUserId(req.user.userId);
            profileId = (companyProfile._id as Types.ObjectId).toString();
          } catch (error) {
            logger.error('[checkChallengeOwnership] Error fetching company profile', {
              userId: req.user.userId,
              error: error instanceof Error ? error.message : String(error)
            });
          }
        }
        
        const results = {
          challenge: {
            id: (challenge._id as Types.ObjectId).toString(),
            companyId: (challenge.company as Types.ObjectId).toString(),
            status: challenge.status
          },
          user: {
            id: req.user?.userId,
            role: req.user?.role,
            profileId: profileId
          },
          ownership: {
            isAdmin: req.user?.role === UserRole.ADMIN,
            isOwner: profileId && challenge.company.toString() === profileId,
            directQueryMatch: false
          }
        };
        
        // Double-check with direct query
        if (profileId) {
          const directMatch = await Challenge.countDocuments({
            _id: id,
            company: profileId
          });
          
          results.ownership.directQueryMatch = directMatch > 0;
        }
        
        logger.info('[checkChallengeOwnership] Diagnostic results', results);
        
        this.sendSuccess(res, results, 'Challenge ownership diagnostic results');
      } catch (error) {
        next(error);
      }
    }
  );

  /**
   * Diagnostic endpoint to list all challenges owned by a company
   * NOT FOR PRODUCTION USE - Debugging only
   */
  listOwnedChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      try {
        // Verify user has company role
        this.verifyAuthorization(req, [UserRole.COMPANY], 'view owned challenges');
        
        logger.info('[listOwnedChallenges] Diagnostic request', {
          userId: req.user!.userId
        });
        
        // Get company profile
        const companyProfile = await this.profileService.getCompanyProfileByUserId(req.user!.userId);
        const companyId = (companyProfile._id as Types.ObjectId).toString();
        
        // Find all challenges owned by this company
        const challenges = await Challenge.find({ company: companyId }).lean();
        
        // Format response
        const result = {
          diagnostic: true,
          companyId,
          userId: req.user!.userId,
          totalChallenges: challenges.length,
          challenges: challenges.map(c => ({
            id: (c._id as Types.ObjectId).toString(),
            title: c.title,
            status: c.status,
            companyId: typeof c.company === 'object' ? 
              ((c.company as any)._id?.toString() || 'n/a') : 
              (c.company as Types.ObjectId)?.toString() || 'n/a'
          }))
        };
        
        logger.info('[listOwnedChallenges] Found challenges', {
          userId: req.user!.userId,
          count: challenges.length
        });
        
        this.sendSuccess(res, result, 'Retrieved owned challenges for diagnostic purposes');
      } catch (error) {
        logger.error('[listOwnedChallenges] Error', {
          userId: req.user?.userId,
          error: error instanceof Error ? error.message : String(error)
        });
        next(error);
      }
    }
  );
}

// Export singleton instance for use in routes
export const challengeController = new ChallengeController();