import { Response, NextFunction } from 'express';
import { ArchitectService } from '../services/architect.service';
import { UserRole } from '../models/interfaces';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catchAsync';

// Instantiate service for controller
const architectService = new ArchitectService();

/**
 * Controller for architect-related operations
 * Extends BaseController for standardized response handling
 * Contains no business logic - delegates to ArchitectService
 */
export class ArchitectController extends BaseController {
  constructor() {
    super();
  }

  /**
   * Get architect profile
   * @route GET /architect/profile
   */
  public getProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has architect role (authorization check)
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      // Delegate to service
      const profile = await architectService.getProfileByUserId(req.user!.userId);
      
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
      const updatedProfile = await architectService.createOrUpdateProfile(
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
      // Authorization via service
      await architectService.authorizeArchitect(req.user!.userId, 'list-solutions');
      
      // Filter parsing and validation via service
      const filters = architectService.parseSolutionFilters(req.query);
      
      // Get solutions via service
      const result = await architectService.getPendingSolutions(filters);
      
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
      // Authorization via service
      await architectService.authorizeArchitect(req.user!.userId, 'view-solution');
      
      // Get solution via service (includes ID validation)
      const solution = await architectService.getSolutionById(req.params.id);
      
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
      // Authorization via service
      const { architectId } = await architectService.authorizeArchitectForSolution(
        req.user!.userId,
        req.params.id,
        'review'
      );
      
      // Validate review data via service
      const reviewData = architectService.validateReviewData(req.body);
      
      // Submit review via service
      const updatedSolution = await architectService.reviewSolution(
        req.params.id,
        architectId,
        reviewData
      );
      
      // Log and respond
      this.logAction('review-solution', req.user!.userId, { 
        solutionId: req.params.id, 
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
   * @route POST /architect/solutions/:id/claim
   */
  public claimSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Authorization via service
      const architectId = await architectService.authorizeArchitect(
        req.user!.userId, 
        'claim-solution'
      );
      
      // Claim solution via service (includes validation)
      const claimedSolution = await architectService.claimSolutionForReview(
        req.params.id,
        architectId
      );
      
      // Log and respond
      this.logAction('claim-solution', req.user!.userId, { solutionId: req.params.id });
      this.sendSuccess(
        res, 
        claimedSolution, 
        'Solution successfully claimed for review'
      );
    }
  );

  /**
   * Get architect dashboard statistics
   * @route GET /architect/dashboard
   */
  public getDashboardStats = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Authorization via service
      const architectId = await architectService.authorizeArchitect(
        req.user!.userId, 
        'dashboard'
      );
      
      // Get stats via service
      const stats = await architectService.getDashboardStats(architectId);
      
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
      // Authorization via service
      const architectId = await architectService.authorizeArchitect(
        req.user!.userId, 
        'select-solutions'
      );
      
      // Validate input data via service
      const validatedSolutionIds = architectService.validateSolutionSelectionData(
        req.params.challengeId,
        req.body.solutionIds
      );
      
      // Process selection via service
      const selectedSolutions = await architectService.selectSolutionsForCompany(
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