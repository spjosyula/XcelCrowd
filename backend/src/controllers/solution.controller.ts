import { Response, NextFunction } from 'express';
import { Types } from 'mongoose';
import Solution from '../models/Solution';
import Challenge from '../models/Challenge';
import { HTTP_STATUS, SolutionStatus, ChallengeStatus, UserRole, IChallenge, IStudentProfile } from '../models/interfaces';
import { SolutionService } from '../services/solution.service';
import StudentProfile from '../models/StudentProfile';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { catchAsync } from '../utils/catchAsync';

/**
 * Controller for solution-related operations
 * Extends BaseController for standardized response handling
 */
export class SolutionController extends BaseController {
  private solutionService: SolutionService;

  constructor() {
    super();
    this.solutionService = new SolutionService();
  }

  /**
   * Type guard to check if challenge is populated (not just an ObjectId)
   * @private
   */
  private isPopulatedChallenge(challenge: Types.ObjectId | IChallenge): challenge is IChallenge {
    return challenge != null && typeof challenge !== 'string' && '_id' in challenge;
  }

  /**
   * Submit a solution to a challenge
   * @route POST /api/solutions
   * @access Private - Student only
   */
  public submitSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.STUDENT]);
      
      const { challenge: challengeId, title, description, submissionUrl, tags } = req.body;
      
      // Validate challengeId
      this.validateObjectId(challengeId, 'challenge');
      
      // Get student profile
      const studentProfile = await StudentProfile.findOne({ user: req.user!.userId });
      
      if (!studentProfile) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Student profile not found');
      }
      
      // Delegate to service with transactions and comprehensive checks
      const solution = await this.solutionService.submitSolution(
        (studentProfile._id as Types.ObjectId).toString(),
        challengeId,
        { title, description, submissionUrl, tags }
      );

      this.logAction('submit-solution', req.user!.userId, { 
        challengeId,
        solutionId: (solution as any)._id.toString()
      });

      this.sendSuccess(
        res, 
        solution, 
        'Solution submitted successfully', 
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Get all solutions submitted by current student
   * @route GET /api/solutions/student
   * @access Private - Student only
   */
  public getStudentSolutions = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const studentId = this.getUserProfileId(req, UserRole.STUDENT);
      
      // Extract query parameters for filtering and pagination
      const { status, page, limit, sortBy, sortOrder } = req.query;
      
      // Delegate to service with enhanced filtering
      const result = await this.solutionService.getStudentSolutions(
        studentId,
        {
          status: status as SolutionStatus,
          page: page ? parseInt(page as string) : undefined,
          limit: limit ? parseInt(limit as string) : undefined,
          sortBy: sortBy as string,
          sortOrder: sortOrder as 'asc' | 'desc'
        }
      );
      
      this.logAction('get-student-solutions', req.user!.userId, {
        count: result.solutions.length,
        status
      });

      this.sendPaginatedSuccess(
        res,
        result.solutions,
        'Student solutions retrieved successfully',
        {
          total: result.total,
          page: result.page,
          limit: result.limit
        }
      );
    }
  );

  /**
   * Get all solutions for a specific challenge
   * @route GET /api/solutions/challenge/:challengeId
   * @access Private - Company (owner) or Architect or Admin
   */
  public getChallengeSolutions = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ARCHITECT, UserRole.ADMIN]);
      
      const { challengeId } = req.params;
      const userRole = req.user!.role as UserRole;
      const profileId = req.user!.profile?.toString();
      
      this.validateObjectId(challengeId, 'challenge');
      
      if (!profileId && userRole !== UserRole.ADMIN) {
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Profile not found');
      }
      
      // Check if challenge exists
      const challenge = await Challenge.findById(challengeId);
      
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }
      
      // Verify permissions:
      // - Architects can view closed challenges
      // - Companies can only view their own challenges
      // - Admins can view all
      if (userRole === UserRole.COMPANY && challenge.company.toString() !== profileId) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN, 
          'You do not have permission to view solutions for this challenge'
        );
      }
      
      // Architects can only view solutions for closed challenges
      if (userRole === UserRole.ARCHITECT && challenge.status !== ChallengeStatus.CLOSED) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN, 
          'Only solutions for closed challenges can be viewed by architects'
        );
      }
      
      // Get solutions
      const solutions = await Solution.find({ challenge: challengeId })
        .populate('student', 'firstName lastName university')
        .populate('reviewedBy', 'firstName lastName')
        .populate('selectedBy', 'firstName lastName')
        .sort({ createdAt: -1 });
      
      this.logAction('get-challenge-solutions', req.user!.userId, {
        challengeId,
        count: solutions.length
      });

      this.sendSuccess(
        res, 
        solutions, 
        'Challenge solutions retrieved successfully', 
        HTTP_STATUS.OK, 
        {
          count: solutions.length
        }
      );
    }
  );

  /**
   * Get solution by ID
   * @route GET /api/solutions/:id
   * @access Private - Solution owner (Student) or Challenge owner (Company) or Architect or Admin
   */
  public getSolutionById = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);
      
      const { id } = req.params;
      const userRole = req.user!.role as UserRole;
      const userId = req.user!.userId;
      
      this.validateObjectId(id, 'solution');
      
      // Delegate to service with enhanced authorization checks
      const solution = await this.solutionService.getSolutionById(id, userId, userRole);
      
      this.logAction('get-solution', req.user!.userId, { solutionId: id });

      this.sendSuccess(res, solution, 'Solution retrieved successfully');
    }
  );

  /**
   * Update a solution (before deadline)
   * @route PUT /api/solutions/:id
   * @access Private - Solution owner (Student) only
   */
  public updateSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const studentId = this.getUserProfileId(req, UserRole.STUDENT);
      
      const { id } = req.params;
      const { title, description, submissionUrl } = req.body;
      
      this.validateObjectId(id, 'solution');
      
      // Delegate to service with transaction support
      const updatedSolution = await this.solutionService.updateSolution(
        id,
        studentId,
        { title, description, submissionUrl }
      );
      
      this.logAction('update-solution', req.user!.userId, { solutionId: id });

      this.sendSuccess(res, updatedSolution, 'Solution updated successfully');
    }
  );

  /**
   * Claim a solution for review
   * @route PATCH /api/solutions/:id/claim
   * @access Private - Architect only
   */
  public claimSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const architectId = this.getUserProfileId(req, UserRole.ARCHITECT);
      
      const { id } = req.params;
      this.validateObjectId(id, 'solution');
      
      // Delegate to service with transaction support
      const updatedSolution = await this.solutionService.claimSolutionForReview(id, architectId);
      
      this.logAction('claim-solution', req.user!.userId, { 
        solutionId: id,
        architectId
      });

      this.sendSuccess(res, updatedSolution, 'Solution claimed for review successfully');
    }
  );

  /**
   * Review a solution (approve/reject with feedback)
   * @route PATCH /api/solutions/:id/review
   * @access Private - Reviewing architect only
   */
  public reviewSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const architectId = this.getUserProfileId(req, UserRole.ARCHITECT);
      
      const { id } = req.params;
      const { status, feedback, score } = req.body;
      
      this.validateObjectId(id, 'solution');
      
      // Validate status
      if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(status)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Status must be either approved or rejected');
      }
      
      // Delegate to service with transaction support
      const updatedSolution = await this.solutionService.reviewSolution(id, architectId, {
        status,
        feedback,
        score
      });
      
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
   * Select a solution as a winner (by company)
   * @route PATCH /api/solutions/:id/select
   * @access Private - Company (challenge owner) only
   */
  public selectSolution = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const companyId = this.getUserProfileId(req, UserRole.COMPANY);
      
      const { id } = req.params;
      this.validateObjectId(id, 'solution');
      
      // Delegate to service with transaction support and proper challenge status workflow
      const updatedSolution = await this.solutionService.selectSolutionAsWinner(id, companyId);
      
      this.logAction('select-solution', req.user!.userId, { 
        solutionId: id,
        companyId
      });

      this.sendSuccess(res, updatedSolution, 'Solution selected as winner successfully');
    }
  );

  /**
   * Get solutions reviewed by current architect
   * @route GET /api/solutions/architect
   * @access Private - Architect only
   */
  public getArchitectReviews = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const architectId = this.getUserProfileId(req, UserRole.ARCHITECT);
      
      const solutions = await Solution.find({ reviewedBy: architectId })
        .populate('challenge', 'title company status')
        .populate('student', 'firstName lastName university')
        .sort({ updatedAt: -1 });
      
      this.logAction('get-architect-reviews', req.user!.userId, {
        count: solutions.length
      });

      this.sendSuccess(
        res, 
        solutions, 
        'Architect reviews retrieved successfully', 
        HTTP_STATUS.OK, 
        {
          count: solutions.length
        }
      );
    }
  );
}

// Export singleton instance for use in routes
export const solutionController = new SolutionController();