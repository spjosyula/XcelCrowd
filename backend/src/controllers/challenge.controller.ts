import { Response, NextFunction } from 'express';
import { Types } from 'mongoose';
import Challenge from '../models/Challenge';
import Solution from '../models/Solution';
import { HTTP_STATUS, ChallengeStatus, SolutionStatus, UserRole } from '../models/interfaces';
import { ChallengeService } from '../services/challenge.service';
import { ProfileService } from '../services/profile.service';
import { ApiError } from '../utils/ApiError';
import { catchAsync } from '../utils/catchAsync';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { logger } from '../utils/logger';

/**
 * Controller for challenge-related operations
 * Extends BaseController for standardized response handling
 */
export class ChallengeController extends BaseController {
  private challengeService: ChallengeService;
  private profileService: ProfileService;

  constructor() {
    super();
    this.challengeService = new ChallengeService();
    this.profileService = new ProfileService();
  }

  /**
   * Create a new challenge
   * @route POST /api/challenges
   * @access Private - Company only
   */
  createChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const companyId = this.getUserProfileId(req, UserRole.COMPANY);
      
      const challengeData = {
        ...req.body,
        company: companyId,
        currentParticipants: 0,
        approvedSolutionsCount: 0
      };

      const challenge = await Challenge.create(challengeData);
      if(!challenge || !challenge._id) {
        throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create challenge');
      }

      this.logAction('challenge-create', req.user!.userId, { 
        challengeId: challenge._id.toString() 
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
   * Get all challenges 
   * @route GET /api/challenges
   * @access Private - Authenticated users only (Student, Company, Admin)
   */
  getAllChallenges = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);

      const { status, difficulty, category, search } = req.query;
      const filters: Record<string, any> = {};
      
      // Apply filters
      if (status) filters.status = status;
      if (difficulty) filters.difficulty = difficulty;
      if (category) filters.category = { $in: Array.isArray(category) ? category : [category] };
      
      // Search in title and description
      if (search) {
        const searchRegex = new RegExp(String(search), 'i');
        filters.$or = [
          { title: searchRegex },
          { description: searchRegex },
          { tags: searchRegex }
        ];
      }

      // Only show active challenges by default
      if (!status) {
        filters.status = ChallengeStatus.ACTIVE;
      }

      // Apply visibility filters based on user role
      const userRole = req.user!.role as UserRole;
      if (userRole === UserRole.STUDENT || !userRole) {
        // For students or public access:
        // - Show public challenges
        // - Show private challenges only if student's university is in allowedInstitutions
        // - Show anonymous challenges without company info
        
        // Initial visibility filter
        const visibilityFilter: Record<string, any> = { visibility: 'public' };
        
        // For authenticated students, also include private challenges they can access
        if (userRole === UserRole.STUDENT && req.user?.userId) {
          try {
            // Get student profile to check university
            const studentProfile = await this.profileService.getStudentProfileByUserId(req.user.userId);
            if (studentProfile?.university) {
              visibilityFilter.$or = [
                { visibility: 'public' },
                { visibility: 'anonymous' },
                { 
                  visibility: 'private', 
                  allowedInstitutions: { $in: [studentProfile.university] } 
                }
              ];
            }
          } catch (error) {
            // If profile can't be found, just use public visibility
            logger.warn('Failed to fetch student profile:', { error, userId: req.user?.userId });
          }
        }
        
        filters.$and = filters.$and || [];
        filters.$and.push(visibilityFilter);
      }

      const challenges = await Challenge.find(filters)
        .populate('company', '-user -__v')
        .select('-__v')
        .sort({ createdAt: -1 });

      // For anonymous challenges, remove company data for non-company users
      const processedChallenges = challenges.map(challenge => {
        const challengeObj = challenge.toObject();
        if (challenge.visibility === 'anonymous' && 
            (userRole !== UserRole.COMPANY && userRole !== UserRole.ADMIN)) {
          // Use optional property access to avoid TypeScript errors
          if (challengeObj.company) {
            const { company, ...rest } = challengeObj;
            return rest;
          }
        }
        return challengeObj;
      });

      this.logAction('challenges-list', req.user!.userId, { 
        count: processedChallenges.length,
        filters: { status, difficulty, category }
      });

      this.sendSuccess(
        res, 
        processedChallenges, 
        'Challenges retrieved successfully',
        HTTP_STATUS.OK,
        { count: processedChallenges.length }
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
      this.verifyAuthorization(req);
      
      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      const challenge = await Challenge.findById(id)
        .populate('company', '-user -__v');

      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check visibility permissions
      const userRole = req.user!.role as UserRole;
      const isCompanyOwner = req.user?.profile && 
                           challenge.company && 
                           typeof challenge.company !== 'string' &&
                           challenge.company._id && 
                           req.user.profile.toString() === challenge.company._id.toString();

      // For private challenges, check institution access for students
      if (challenge.visibility === 'private' && userRole === UserRole.STUDENT) {
        try {
          // Get student profile to check university
          const studentProfile = await this.profileService.getStudentProfileByUserId(req.user!.userId);
          
          // Check if student's university is in allowed institutions
          if (!studentProfile?.university || 
              !challenge.allowedInstitutions?.includes(studentProfile.university)) {
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN, 
              'You do not have permission to view this private challenge'
            );
          }
        } catch (error) {
          if (error instanceof ApiError) {
            throw error;
          }
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN, 
            'Failed to verify access to this challenge'
          );
        }
      }

      // Create a mutable copy of the challenge
      const challengeObj = challenge.toObject();

      // For anonymous challenges, hide company data for non-owners and non-admins
      if (challenge.visibility === 'anonymous' && 
          (!isCompanyOwner && userRole !== UserRole.ADMIN)) {
        if (challengeObj.company) {
          const { company, ...restChallenge } = challengeObj;
          
          this.logAction('challenge-view', req.user!.userId, { 
            challengeId: id, 
            anonymous: true 
          });
          
          this.sendSuccess(res, restChallenge, 'Challenge retrieved successfully');
          return;
        }
      }

      this.logAction('challenge-view', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, challengeObj, 'Challenge retrieved successfully');
    }
  );

  /**
   * Update challenge
   * @route PUT /api/challenges/:id
   * @access Private - Company only (owner)
   */
  updateChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN]);

      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      // Get challenge to verify ownership
      const challenge = await Challenge.findById(id);
      
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check ownership if not admin
      const userRole = req.user!.role as UserRole;
      if (userRole !== UserRole.ADMIN) {
        const companyId = this.getUserProfileId(req, UserRole.COMPANY);
        
        // Convert ObjectId to string for comparison if needed
        const challengeCompanyId = challenge.company instanceof Types.ObjectId 
          ? challenge.company.toString() 
          : challenge.company;
          
        if (challengeCompanyId !== companyId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN, 
            'You do not have permission to update this challenge'
          );
        }
      }

      // Don't allow changing the status directly (use dedicated endpoints)
      // Also don't allow changing essential properties once challenge is active
      if (challenge.status !== ChallengeStatus.DRAFT && 
          (req.body.status || 
           req.body.reward || 
           req.body.minReward || 
           req.body.maxReward ||
           req.body.duration)) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'Cannot modify status, reward or duration of an active or completed challenge'
        );
      }

      // Update the challenge
      const updatedChallenge = await Challenge.findByIdAndUpdate(
        id,
        { $set: req.body },
        { new: true, runValidators: true }
      ).populate('company', '-user -__v');

      this.logAction('challenge-update', req.user!.userId, { challengeId: id });
      this.sendSuccess(res, updatedChallenge, 'Challenge updated successfully');
    }
  );

  /**
   * Delete challenge
   * @route DELETE /api/challenges/:id
   * @access Private - Company only (owner) or Admin
   */
  deleteChallenge = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN]);

      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      // Get challenge to verify ownership
      const challenge = await Challenge.findById(id);
      
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check ownership if not admin
      const userRole = req.user!.role as UserRole;
      if (userRole !== UserRole.ADMIN) {
        const companyId = this.getUserProfileId(req, UserRole.COMPANY);
        
        // Convert ObjectId to string for comparison if needed
        const challengeCompanyId = challenge.company instanceof Types.ObjectId 
          ? challenge.company.toString() 
          : challenge.company;
          
        if (challengeCompanyId !== companyId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN, 
            'You do not have permission to delete this challenge'
          );
        }
      }

      // Don't allow deletion of active or completed challenges with participants
      if (challenge.status !== ChallengeStatus.DRAFT && challenge.currentParticipants > 0) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'Cannot delete an active or completed challenge with participants'
        );
      }

      // Delete the challenge
      await Challenge.findByIdAndDelete(id);

      // Also delete any solutions for this challenge
      await Solution.deleteMany({ challenge: id });

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
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN]);

      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      // Get challenge to verify ownership
      const challenge = await Challenge.findById(id);
      
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check ownership if not admin
      const userRole = req.user!.role as UserRole;
      if (userRole !== UserRole.ADMIN) {
        const companyId = this.getUserProfileId(req, UserRole.COMPANY);
        
        // Convert ObjectId to string for comparison if needed
        const challengeCompanyId = challenge.company instanceof Types.ObjectId 
          ? challenge.company.toString() 
          : challenge.company;
          
        if (challengeCompanyId !== companyId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN, 
            'You do not have permission to close this challenge'
          );
        }
      }

      // Only active challenges can be closed
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot close a challenge that is ${challenge.status}`
        );
      }

      // Update the challenge status
      const updatedChallenge = await Challenge.findByIdAndUpdate(
        id,
        { $set: { status: ChallengeStatus.CLOSED } },
        { new: true, runValidators: true }
      ).populate('company', '-user -__v');

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
      this.verifyAuthorization(req, [UserRole.COMPANY, UserRole.ADMIN]);

      const { id } = req.params;
      this.validateObjectId(id, 'challenge');

      // Get challenge to verify ownership
      const challenge = await Challenge.findById(id);
      
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check ownership if not admin
      const userRole = req.user!.role as UserRole;
      if (userRole !== UserRole.ADMIN) {
        const companyId = this.getUserProfileId(req, UserRole.COMPANY);
        
        // Convert ObjectId to string for comparison if needed
        const challengeCompanyId = challenge.company instanceof Types.ObjectId 
          ? challenge.company.toString() 
          : challenge.company;
          
        if (challengeCompanyId !== companyId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN, 
            'You do not have permission to complete this challenge'
          );
        }
      }

      // Only closed challenges can be marked as completed
      if (challenge.status !== ChallengeStatus.CLOSED) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot complete a challenge that is ${challenge.status}. Challenge must be closed first.`
        );
      }

      // Update the challenge status
      const updatedChallenge = await Challenge.findByIdAndUpdate(
        id,
        { $set: { status: ChallengeStatus.COMPLETED } },
        { new: true, runValidators: true }
      ).populate('company', '-user -__v');

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
      const companyId = this.getUserProfileId(req, UserRole.COMPANY);

      const { status } = req.query;
      const filters: Record<string, any> = { company: companyId };
      
      // Apply status filter if provided
      if (status) {
        filters.status = status;
      }

      const challenges = await Challenge.find(filters)
        .populate('company', '-user -__v')
        .select('-__v')
        .sort({ createdAt: -1 });

      this.logAction('company-challenges-list', req.user!.userId, { 
        count: challenges.length,
        filters: { status }
      });

      this.sendSuccess(
        res,
        challenges,
        'Company challenges retrieved successfully',
        HTTP_STATUS.OK,
        { count: challenges.length }
      );
    }
  );
}

// Export a singleton instance for use in routes
export const challengeController = new ChallengeController();