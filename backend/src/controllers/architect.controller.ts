import { Request, Response, NextFunction } from 'express';
import { ArchitectService } from '../services/architect.service';
import { 
  architectProfileSchema, 
  reviewSolutionSchema, 
  filterSolutionsSchema 
} from '../validations/architect.validation';
import { ApiError } from '../utils/ApiError';
import { SolutionStatus, UserRole } from '../models/interfaces';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catchAsync';
import { HTTP_STATUS } from '../constants';

/**
 * Controller for architect-related operations
 * Extends BaseController for standardized response handling
 */
export class ArchitectController extends BaseController {
  private architectService: ArchitectService;

  constructor() {
    super();
    this.architectService = new ArchitectService();
  }

  /**
   * Get architect profile
   * @route GET /architect/profile
   */
  public getProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const profileId = this.getUserProfileId(req, UserRole.ARCHITECT);
      const profile = await this.architectService.getProfileByUserId(req.user!.userId);
      
      this.logAction('get-profile', req.user!.userId, { profileId });
      this.sendSuccess(res, profile, 'Architect profile retrieved successfully');
    }
  );

  /**
   * Create or update architect profile
   * @route PUT /architect/profile
   */
  public updateProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      // Validate request data
      const validatedData = architectProfileSchema.parse(req.body);
      
      const updatedProfile = await this.architectService.createOrUpdateProfile(
        req.user!.userId, 
        validatedData
      );
      
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
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      // Validate and parse query parameters
      const filters = filterSolutionsSchema.parse({
        status: req.query.status as SolutionStatus | undefined,
        challengeId: req.query.challengeId as string | undefined,
        studentId: req.query.studentId as string | undefined,
        page: req.query.page ? parseInt(req.query.page as string) : undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string) : undefined
      });
      
      const result = await this.architectService.getPendingSolutions(filters);
      
      this.sendPaginatedSuccess(
        res,
        result.solutions,
        'Pending solutions retrieved successfully',
        {
          total: result.total,
          page: result.page,
          limit: result.limit
        }
      );
    }
  );

  /**
   * Get a specific solution by ID
   * @route GET /architect/solutions/:id
   */
  public getSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      const solutionId = req.params.id;
      this.validateObjectId(solutionId, 'solution');
      
      const solution = await this.architectService.getSolutionById(solutionId);
      
      this.sendSuccess(res, solution, 'Solution retrieved successfully');
    }
  );

  /**
   * Review a solution
   * @route POST /architect/solutions/:id/review
   */
  public reviewSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      const solutionId = req.params.id;
      this.validateObjectId(solutionId, 'solution');
      
      // Validate review data
      const reviewData = reviewSolutionSchema.parse(req.body);
      
      // Get architect profile
      const architectProfile = await this.architectService.getProfileByUserId(req.user!.userId);
      if (!architectProfile || !architectProfile._id) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
      }
      const architectId = architectProfile._id.toString();
      
      const updatedSolution = await this.architectService.reviewSolution(
        solutionId,
        architectId,
        reviewData
      );
      
      this.logAction('review-solution', req.user!.userId, { 
        solutionId, 
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
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      const solutionId = req.params.id;
      this.validateObjectId(solutionId, 'solution');
      
      // Get architect profile
      const architectProfile = await this.architectService.getProfileByUserId(req.user!.userId);
      if (!architectProfile || !architectProfile._id) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
      }
      const architectId = architectProfile._id.toString();
      
      const claimedSolution = await this.architectService.claimSolutionForReview(
        solutionId,
        architectId
      );
      
      this.logAction('claim-solution', req.user!.userId, { solutionId });
      
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
        this.verifyAuthorization(req, [UserRole.ARCHITECT]);
        
        // Get architect profile
        const architectProfile = await this.architectService.getProfileByUserId(req.user!.userId);
        if (!architectProfile || !architectProfile._id) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
        }
        const architectId = architectProfile._id.toString();
        
        const stats = await this.architectService.getDashboardStats(architectId);
        
        this.sendSuccess(res, stats, 'Dashboard statistics retrieved successfully');
      }
    );

  /**
   * Select approved solutions to forward to the company
   * @route POST /architect/challenges/:challengeId/select-solutions
   */
  public selectSolutionsForCompany = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.ARCHITECT]);
      
      const challengeId = req.params.challengeId;
      this.validateObjectId(challengeId, 'challenge');
      
      const { solutionIds } = req.body;
      
      if (!Array.isArray(solutionIds) || solutionIds.length === 0) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST, 
          'At least one solution ID must be provided'
        );
      }
      
      // Validate each solution ID
      solutionIds.forEach(id => this.validateObjectId(id, 'solution'));
      
      // Get architect profile
      const architectProfile = await this.architectService.getProfileByUserId(req.user!.userId);
      if (!architectProfile || !architectProfile._id) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
      }
      const architectId = architectProfile._id.toString();
      
      const selectedSolutions = await this.architectService.selectSolutionsForCompany(
        challengeId,
        solutionIds,
        architectId
      );
      
      this.logAction('select-solutions', req.user!.userId, { 
        challengeId, 
        solutionCount: solutionIds.length 
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