import { Request, Response, NextFunction } from 'express';
import { ArchitectService } from '../services/architect.service';
import { architectProfileSchema, reviewSolutionSchema, filterSolutionsSchema } from '../validations/architect.validation';
import { ApiError } from '../utils/ApiError';
import { SolutionStatus, IArchitectProfile } from '../models/interfaces';
import { Types } from 'mongoose';

// Define the user property in the Request interface
declare global {
  namespace Express {
    interface User {
      userId: string;
      email: string;
      role: string;
    }
  }
}

/**
 * Controller for architect-related operations
 */
export class ArchitectController {
  private architectService: ArchitectService;

  constructor() {
    this.architectService = new ArchitectService();
  }

  /**
   * Get architect profile
   * @route GET /architect/profile
   */
  getProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        throw ApiError.unauthorized('User not authenticated');
      }

      const profile = await this.architectService.getProfileByUserId(userId);
      
      res.status(200).json({
        success: true,
        data: profile
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Create or update architect profile
   * @route PUT /architect/profile
   */
  updateProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        throw ApiError.unauthorized('User not authenticated');
      }

      const validatedData = architectProfileSchema.parse(req.body);
      
      const updatedProfile = await this.architectService.createOrUpdateProfile(userId, validatedData);
      
      res.status(200).json({
        success: true,
        data: updatedProfile
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Get pending solutions for review
   * @route GET /architect/solutions
   */
  getPendingSolutions = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const filters = filterSolutionsSchema.parse({
        status: req.query.status as SolutionStatus | undefined,
        challengeId: req.query.challengeId as string | undefined,
        studentId: req.query.studentId as string | undefined,
        page: req.query.page ? parseInt(req.query.page as string) : undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string) : undefined
      });
      
      const result = await this.architectService.getPendingSolutions(filters);
      
      res.status(200).json({
        success: true,
        data: result.solutions,
        pagination: {
          total: result.total,
          page: result.page,
          limit: result.limit,
          pages: Math.ceil(result.total / result.limit)
        }
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Get a specific solution by ID
   * @route GET /architect/solutions/:id
   */
  getSolution = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const solutionId = req.params.id;
      
      const solution = await this.architectService.getSolutionById(solutionId);
      
      res.status(200).json({
        success: true,
        data: solution
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Review a solution
   * @route POST /architect/solutions/:id/review
   */
  reviewSolution = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        throw ApiError.unauthorized('User not authenticated');
      }

      const solutionId = req.params.id;
      const reviewData = reviewSolutionSchema.parse(req.body);
      
      // Get architect profile ID
      const architectProfile = await this.architectService.getProfileByUserId(userId);
      // Get the ID as a string safely
      const architectId = (architectProfile as any)._id.toString();
      
      const updatedSolution = await this.architectService.reviewSolution(
        solutionId,
        architectId,
        reviewData
      );
      
      res.status(200).json({
        success: true,
        data: updatedSolution
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Claim a solution for review
   * @route POST /architect/solutions/:id/claim
   */
  claimSolution = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        throw ApiError.unauthorized('User not authenticated');
      }

      const solutionId = req.params.id;
      
      // Get architect profile ID
      const architectProfile = await this.architectService.getProfileByUserId(userId);
      // Get the ID as a string safely
      const architectId = (architectProfile as any)._id.toString();
      
      const claimedSolution = await this.architectService.claimSolutionForReview(
        solutionId,
        architectId
      );
      
      res.status(200).json({
        success: true,
        data: claimedSolution
      });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Get architect dashboard statistics
   * @route GET /architect/dashboard
   */
  getDashboardStats = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        throw ApiError.unauthorized('User not authenticated');
      }

      // Get architect profile ID
      const architectProfile = await this.architectService.getProfileByUserId(userId);
      // Get the ID as a string safely
      const architectId = (architectProfile as any)._id.toString();
      
      const stats = await this.architectService.getDashboardStats(architectId);
      
      res.status(200).json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  };

    /**
   * Select approved solutions to forward to the company
   * @route POST /architect/challenges/:challengeId/select-solutions
   */
    selectSolutionsForCompany = async (req: Request, res: Response, next: NextFunction) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          throw ApiError.unauthorized('User not authenticated');
        }
  
        const challengeId = req.params.challengeId;
        const { solutionIds } = req.body;
  
        if (!Array.isArray(solutionIds) || solutionIds.length === 0) {
          throw ApiError.badRequest('At least one solution ID must be provided');
        }
  
        // Get architect profile ID
        const architectProfile = await this.architectService.getProfileByUserId(userId);
        const architectId = (architectProfile as any)._id.toString();
        
        // Call service method to select solutions
        const selectedSolutions = await this.architectService.selectSolutionsForCompany(
          challengeId,
          solutionIds,
          architectId
        );
        
        res.status(200).json({
          success: true,
          data: selectedSolutions,
          message: 'Solutions have been successfully selected for the company'
        });
      } catch (error) {
        next(error);
      }
    };
} 