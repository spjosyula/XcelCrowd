import { Request, Response } from 'express';
import { Types } from 'mongoose';
import Challenge from '../models/Challenge';
import Solution from '../models/Solution';
import { HTTP_STATUS, ChallengeStatus, SolutionStatus, UserRole } from '../models/interfaces';
import { ChallengeService } from '../services/challenge.service';
import { ProfileService } from '../services/profile.service';

// Extended interface for Request with user property
interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role: string;
    profile?: Types.ObjectId | string;
  };
}

// Initialize services
const challengeService = new ChallengeService();
const profileService = new ProfileService();

/**
 * Create a new challenge
 * @route POST /api/challenges
 * @access Private - Company only
 */
export const createChallenge = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }

    const companyId = req.user.profile?.toString();
    
    if (!companyId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Company profile not found' 
      });
      return;
    }

    const challengeData = {
      ...req.body,
      company: companyId,
      currentParticipants: 0,
      approvedSolutionsCount: 0
    };

    const challenge = await Challenge.create(challengeData);

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      data: challenge,
      message: 'Challenge created successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to create challenge'
    });
  }
};

/**
 * Get all challenges 
 * @route GET /api/challenges
 * @access Public
 */
export const getAllChallenges = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
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
    const userRole = req.user?.role;
    if (!userRole || userRole === UserRole.STUDENT) {
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
          const studentProfile = await profileService.getStudentProfileByUserId(req.user.userId);
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
          console.error('Failed to fetch student profile:', error);
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
          (!userRole || (userRole !== UserRole.COMPANY && userRole !== UserRole.ADMIN))) {
        // Use optional property access to avoid TypeScript errors
        if (challengeObj.company) {
          const { company, ...rest } = challengeObj;
          return rest;
        }
      }
      return challengeObj;
    });

    res.status(HTTP_STATUS.OK).json({
      success: true,
      count: processedChallenges.length,
      data: processedChallenges
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch challenges'
    });
  }
};

/**
 * Get challenge by ID
 * @route GET /api/challenges/:id
 * @access Public
 */
export const getChallengeById = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    const challenge = await Challenge.findById(id)
      .populate('company', '-user -__v');

    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }

    // Check visibility permissions
    const userRole = req.user?.role;
    const isCompanyOwner = req.user?.profile && 
                           challenge.company && 
                           typeof challenge.company !== 'string' &&
                           challenge.company._id && 
                           req.user.profile.toString() === challenge.company._id.toString();

    // Handle private challenges
    if (challenge.visibility === 'private' && userRole === UserRole.STUDENT && req.user?.userId) {
      try {
        const studentProfile = await profileService.getStudentProfileByUserId(req.user.userId);
        const studentUniversity = studentProfile?.university;
        
        if (!studentUniversity || !challenge.allowedInstitutions?.includes(studentUniversity)) {
          res.status(HTTP_STATUS.FORBIDDEN).json({ 
            success: false, 
            message: 'You do not have permission to view this challenge' 
          });
          return;
        }
      } catch (error) {
        res.status(HTTP_STATUS.FORBIDDEN).json({ 
          success: false, 
          message: 'Failed to verify permissions' 
        });
        return;
      }
    }

    // Create a mutable copy of the challenge
    const challengeObj = challenge.toObject();

    // For anonymous challenges, hide company data for non-owners and non-admins
    if (challenge.visibility === 'anonymous' && !isCompanyOwner && userRole !== UserRole.ADMIN) {
      if (challengeObj.company) {
        const { company, ...rest } = challengeObj;
        res.status(HTTP_STATUS.OK).json({
          success: true,
          data: rest
        });
        return;
      }
    }

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: challengeObj
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch challenge'
    });
  }
};

/**
 * Update challenge
 * @route PUT /api/challenges/:id
 * @access Private - Challenge owner (company) only
 */
export const updateChallenge = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    
    if (!req.user || !req.user.profile) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const companyId = req.user.profile;
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    // Find challenge and ensure it belongs to the requesting company
    const challenge = await Challenge.findById(id);
    
    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }

    // Verify ownership
    if (challenge.company.toString() !== companyId.toString()) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to update this challenge' 
      });
      return;
    }

    // Prevent updates to closed or completed challenges
    if (challenge.status === ChallengeStatus.CLOSED || challenge.status === ChallengeStatus.COMPLETED) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Cannot update a closed or completed challenge' 
      });
      return;
    }

    // Update challenge
    const updatedChallenge = await Challenge.findByIdAndUpdate(
      id,
      { $set: req.body },
      { new: true, runValidators: true }
    ).populate('company', '-user -__v');

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedChallenge,
      message: 'Challenge updated successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to update challenge'
    });
  }
};

/**
 * Delete challenge
 * @route DELETE /api/challenges/:id
 * @access Private - Challenge owner (company) or admin only
 */
export const deleteChallenge = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const userRole = req.user.role;
    const profileId = req.user.profile;
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    // Find challenge
    const challenge = await Challenge.findById(id);
    
    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }

    // Verify ownership or admin access
    if (userRole !== UserRole.ADMIN && 
        (!profileId || challenge.company.toString() !== profileId.toString())) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to delete this challenge' 
      });
      return;
    }

    // Don't allow deletion if solutions exist
    const solutionsCount = await Solution.countDocuments({ challenge: id });
    
    if (solutionsCount > 0) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Cannot delete challenge with existing solutions. Consider closing it instead.' 
      });
      return;
    }

    await Challenge.findByIdAndDelete(id);

    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: 'Challenge deleted successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to delete challenge'
    });
  }
};

/**
 * Close a challenge for submissions
 * @route PATCH /api/challenges/:id/close
 * @access Private - Challenge owner (company) only
 */
export const closeChallenge = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    
    if (!req.user || !req.user.profile) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const companyId = req.user.profile;
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    // Find challenge and ensure it belongs to the requesting company
    const challenge = await Challenge.findById(id);
    
    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }

    // Verify ownership
    if (challenge.company.toString() !== companyId.toString()) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to close this challenge' 
      });
      return;
    }

    // Update challenge status to closed
    const updatedChallenge = await Challenge.findByIdAndUpdate(
      id,
      { $set: { status: ChallengeStatus.CLOSED } },
      { new: true, runValidators: true }
    );

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedChallenge,
      message: 'Challenge closed successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to close challenge'
    });
  }
};

/**
 * Complete a challenge (finalize after review process)
 * @route PATCH /api/challenges/:id/complete
 * @access Private - Challenge owner (company) only
 */
export const completeChallenge = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    
    if (!req.user || !req.user.profile) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const companyId = req.user.profile;
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    // Find challenge and ensure it belongs to the requesting company
    const challenge = await Challenge.findById(id);
    
    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }

    // Verify ownership
    if (challenge.company.toString() !== companyId.toString()) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to complete this challenge' 
      });
      return;
    }

    // Ensure challenge is closed before completing
    if (challenge.status !== ChallengeStatus.CLOSED) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Challenge must be closed before it can be completed' 
      });
      return;
    }

    // Update challenge status to completed
    const updatedChallenge = await Challenge.findByIdAndUpdate(
      id,
      { $set: { status: ChallengeStatus.COMPLETED } },
      { new: true, runValidators: true }
    );

    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedChallenge,
      message: 'Challenge marked as completed successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to complete challenge'
    });
  }
};

/**
 * Get challenges created by current company
 * @route GET /api/challenges/company
 * @access Private - Company only
 */
export const getCompanyChallenges = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user || !req.user.profile) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const companyId = req.user.profile;

    const challenges = await Challenge.find({ 
      company: companyId.toString()
    }).sort({ createdAt: -1 });

    res.status(HTTP_STATUS.OK).json({
      success: true,
      count: challenges.length,
      data: challenges
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch company challenges'
    });
  }
};