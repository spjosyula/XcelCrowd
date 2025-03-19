import { Request, Response } from 'express';
import { Types } from 'mongoose';
import Solution from '../models/Solution';
import Challenge from '../models/Challenge';
import { HTTP_STATUS, SolutionStatus, ChallengeStatus, UserRole, IChallenge } from '../models/interfaces';
import { SolutionService } from '../services/solution.service';

// Interface for Request with user property
interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role: string;
    profile?: Types.ObjectId | string;
  };
}

// Type guard to check if challenge is populated (not just an ObjectId)
function isPopulatedChallenge(challenge: Types.ObjectId | IChallenge): challenge is IChallenge {
  return challenge != null && typeof challenge !== 'string' && '_id' in challenge;
}

// Initialize services
const solutionService = new SolutionService();

/**
 * Submit a solution to a challenge
 * @route POST /api/solutions
 * @access Private - Student only
 */
export const submitSolution = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }

    const studentId = req.user.profile?.toString();
    const { challengeId, title, description, submissionUrl } = req.body;
    
    if (!studentId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Student profile not found' 
      });
      return;
    }
    
    if (!Types.ObjectId.isValid(challengeId)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }

    try {
      // Use the service to handle business logic
      const solution = await solutionService.submitSolution(
        studentId,
        challengeId,
        { title, description, submissionUrl }
      );

      res.status(HTTP_STATUS.CREATED).json({
        success: true,
        data: solution,
        message: 'Solution submitted successfully'
      });
    } catch (serviceError: any) {
      // Handle expected business logic errors
      res.status(serviceError.status || HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        message: serviceError.message
      });
    }
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to submit solution'
    });
  }
};

/**
 * Get all solutions submitted by current student
 * @route GET /api/solutions/student
 * @access Private - Student only
 */
export const getStudentSolutions = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const studentId = req.user.profile?.toString();
    
    if (!studentId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Student profile not found' 
      });
      return;
    }
    
    const solutions = await Solution.find({ student: studentId })
      .populate('challenge', 'title company status deadline')
      .populate('reviewedBy', 'firstName lastName')
      .populate('selectedBy', 'firstName lastName')
      .sort({ createdAt: -1 });
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      count: solutions.length,
      data: solutions
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch student solutions'
    });
  }
};

/**
 * Get all solutions for a specific challenge
 * @route GET /api/solutions/challenge/:challengeId
 * @access Private - Company (owner) or Architect or Admin
 */
export const getChallengeSolutions = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { challengeId } = req.params;
    const userRole = req.user.role;
    const profileId = req.user.profile?.toString();
    
    if (!Types.ObjectId.isValid(challengeId)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid challenge ID' 
      });
      return;
    }
    
    if (!profileId && userRole !== UserRole.ADMIN) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Profile not found' 
      });
      return;
    }
    
    // Check if challenge exists
    const challenge = await Challenge.findById(challengeId);
    
    if (!challenge) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Challenge not found' 
      });
      return;
    }
    
    // Verify permissions:
    // - Architects can view closed challenges
    // - Companies can only view their own challenges
    // - Admins can view all
    if (userRole === UserRole.COMPANY && challenge.company.toString() !== profileId) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to view solutions for this challenge' 
      });
      return;
    }
    
    // Architects can only view solutions for closed challenges
    if (userRole === UserRole.ARCHITECT && challenge.status !== ChallengeStatus.CLOSED) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Only solutions for closed challenges can be viewed by architects' 
      });
      return;
    }
    
    // Get solutions
    const solutions = await Solution.find({ challenge: challengeId })
      .populate('student', 'firstName lastName university')
      .populate('reviewedBy', 'firstName lastName')
      .populate('selectedBy', 'firstName lastName')
      .sort({ createdAt: -1 });
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      count: solutions.length,
      data: solutions
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch challenge solutions'
    });
  }
};

/**
 * Get solution by ID
 * @route GET /api/solutions/:id
 * @access Private - Solution owner (Student) or Challenge owner (Company) or Architect or Admin
 */
export const getSolutionById = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { id } = req.params;
    const userRole = req.user.role;
    const profileId = req.user.profile?.toString();
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid solution ID' 
      });
      return;
    }
    
    if (!profileId && userRole !== UserRole.ADMIN) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Profile not found' 
      });
      return;
    }
    
    const solution = await Solution.findById(id)
      .populate('challenge')
      .populate('student', 'firstName lastName university')
      .populate('reviewedBy', 'firstName lastName')
      .populate('selectedBy', 'firstName lastName');
    
    if (!solution) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Solution not found' 
      });
      return;
    }
    
    // Verify permissions using type guards for populated fields
    const populatedStudent = solution.student && typeof solution.student !== 'string' && '_id' in solution.student;
    const isStudent = userRole === UserRole.STUDENT && 
                     populatedStudent &&
                     solution.student._id?.toString() === profileId;
    
    const isCompany = userRole === UserRole.COMPANY && 
                     solution.challenge && 
                     isPopulatedChallenge(solution.challenge) &&
                     solution.challenge.company && 
                     solution.challenge.company.toString() === profileId;
                     
    const isArchitect = userRole === UserRole.ARCHITECT;
    const isAdmin = userRole === UserRole.ADMIN;
    
    // Only allow access to authorized users
    if (!isStudent && !isCompany && !isArchitect && !isAdmin) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to view this solution' 
      });
      return;
    }
    
    // Architects can only view solutions for closed challenges
    if (isArchitect && 
        isPopulatedChallenge(solution.challenge) && 
        solution.challenge.status !== ChallengeStatus.CLOSED) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Only solutions for closed challenges can be viewed by architects' 
      });
      return;
    }
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: solution
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch solution'
    });
  }
};

/**
 * Update a solution (before deadline)
 * @route PUT /api/solutions/:id
 * @access Private - Solution owner (Student) only
 */
export const updateSolution = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { id } = req.params;
    const studentId = req.user.profile?.toString();
    const { title, description, submissionUrl } = req.body;
    
    if (!studentId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Student profile not found' 
      });
      return;
    }
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid solution ID' 
      });
      return;
    }
    
    // Find solution and check ownership
    const solution = await Solution.findById(id).populate('challenge');
    
    if (!solution) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Solution not found' 
      });
      return;
    }
    
    // Verify student ownership
    if (solution.student.toString() !== studentId) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to update this solution' 
      });
      return;
    }
    
    // Check if solution is already under review or past that stage
    if (solution.status !== SolutionStatus.SUBMITTED) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: `Cannot update a solution with status: ${solution.status}` 
      });
      return;
    }
    
    // Check if challenge deadline has passed using type guard
    if (isPopulatedChallenge(solution.challenge) && 
        solution.challenge.deadline && 
        new Date() > solution.challenge.deadline) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Cannot update solution after the challenge deadline' 
      });
      return;
    }
    
    // Update solution
    const updatedSolution = await Solution.findByIdAndUpdate(
      id,
      { $set: { title, description, submissionUrl } },
      { new: true, runValidators: true }
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedSolution,
      message: 'Solution updated successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to update solution'
    });
  }
};

/**
 * Claim a solution for review
 * @route PATCH /api/solutions/:id/claim
 * @access Private - Architect only
 */
export const claimSolution = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { id } = req.params;
    const architectId = req.user.profile?.toString();
    
    if (!architectId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Architect profile not found' 
      });
      return;
    }
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid solution ID' 
      });
      return;
    }
    
    // Find solution
    const solution = await Solution.findById(id).populate('challenge');
    
    if (!solution) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Solution not found' 
      });
      return;
    }
    
    // Check if challenge is closed for review using type guard
    if (isPopulatedChallenge(solution.challenge) && 
        solution.challenge.status !== ChallengeStatus.CLOSED) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Solutions can only be claimed for closed challenges' 
      });
      return;
    }
    
    // Check if solution is already claimed
    if (solution.status !== SolutionStatus.SUBMITTED) {
      res.status(HTTP_STATUS.CONFLICT).json({ 
        success: false, 
        message: `Solution is already in status: ${solution.status}` 
      });
      return;
    }
    
    // Update solution to under review status
    const updatedSolution = await Solution.findByIdAndUpdate(
      id,
      { 
        $set: { 
          status: SolutionStatus.UNDER_REVIEW, 
          reviewedBy: architectId 
        } 
      },
      { new: true, runValidators: true }
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedSolution,
      message: 'Solution claimed for review successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to claim solution'
    });
  }
};

/**
 * Review a solution (approve/reject with feedback)
 * @route PATCH /api/solutions/:id/review
 * @access Private - Reviewing architect only
 */
export const reviewSolution = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { id } = req.params;
    const architectId = req.user.profile?.toString();
    const { status, feedback, score } = req.body;
    
    if (!architectId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Architect profile not found' 
      });
      return;
    }
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid solution ID' 
      });
      return;
    }
    
    // Validate status
    if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(status)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Status must be either approved or rejected' 
      });
      return;
    }
    
    // Find solution
    const solution = await Solution.findById(id).populate('challenge');
    
    if (!solution) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Solution not found' 
      });
      return;
    }
    
    // Verify reviewer is the claiming architect
    if (!solution.reviewedBy || solution.reviewedBy.toString() !== architectId) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'Only the architect who claimed this solution can review it' 
      });
      return;
    }
    
    // Verify solution is in UNDER_REVIEW status
    if (solution.status !== SolutionStatus.UNDER_REVIEW) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: `Cannot review a solution with status: ${solution.status}` 
      });
      return;
    }
    
    // For approvals, check if challenge has reached approval limit using type guard
    if (status === SolutionStatus.APPROVED && isPopulatedChallenge(solution.challenge)) {
      const challenge = solution.challenge;
      
      // Check if the challenge has a isApprovalLimitReached method
      if (typeof challenge.isApprovalLimitReached === 'function' && challenge.isApprovalLimitReached()) {
        res.status(HTTP_STATUS.BAD_REQUEST).json({ 
          success: false, 
          message: 'Challenge has reached maximum number of approved solutions' 
        });
        return;
      }
      
      // Increment approved solutions count
      await Challenge.findByIdAndUpdate(
        challenge._id,
        { $inc: { approvedSolutionsCount: 1 } }
      );
    }
    
    // Update solution with review data
    const updatedSolution = await Solution.findByIdAndUpdate(
      id,
      { 
        $set: { 
          status,
          feedback,
          score,
          reviewedAt: new Date() 
        } 
      },
      { new: true, runValidators: true }
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedSolution,
      message: `Solution ${status === SolutionStatus.APPROVED ? 'approved' : 'rejected'} successfully`
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to review solution'
    });
  }
};

/**
 * Select a solution as a winner (by company)
 * @route PATCH /api/solutions/:id/select
 * @access Private - Company (challenge owner) only
 */
export const selectSolution = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const { id } = req.params;
    const companyId = req.user.profile?.toString();
    
    if (!companyId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Company profile not found' 
      });
      return;
    }
    
    if (!Types.ObjectId.isValid(id)) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Invalid solution ID' 
      });
      return;
    }
    
    // Find solution
    const solution = await Solution.findById(id).populate('challenge');
    
    if (!solution) {
      res.status(HTTP_STATUS.NOT_FOUND).json({ 
        success: false, 
        message: 'Solution not found' 
      });
      return;
    }
    
    // Verify company owns the challenge using type guard
    if (!isPopulatedChallenge(solution.challenge) || 
        !solution.challenge.company || 
        solution.challenge.company.toString() !== companyId) {
      res.status(HTTP_STATUS.FORBIDDEN).json({ 
        success: false, 
        message: 'You do not have permission to select a solution for this challenge' 
      });
      return;
    }
    
    // Verify solution is in APPROVED status
    if (solution.status !== SolutionStatus.APPROVED) {
      res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        success: false, 
        message: 'Only approved solutions can be selected as winners' 
      });
      return;
    }
    
    // Update solution to selected status
    const updatedSolution = await Solution.findByIdAndUpdate(
      id,
      { 
        $set: { 
          status: SolutionStatus.SELECTED,
          selectedAt: new Date(),
          selectedBy: solution.reviewedBy 
        } 
      },
      { new: true, runValidators: true }
    );
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: updatedSolution,
      message: 'Solution selected as winner successfully'
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to select solution'
    });
  }
};

/**
 * Get solutions reviewed by current architect
 * @route GET /api/solutions/architect
 * @access Private - Architect only
 */
export const getArchitectReviews = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Authentication required' 
      });
      return;
    }
    
    const architectId = req.user.profile?.toString();
    
    if (!architectId) {
      res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false, 
        message: 'Architect profile not found' 
      });
      return;
    }
    
    const solutions = await Solution.find({ reviewedBy: architectId })
      .populate('challenge', 'title company status')
      .populate('student', 'firstName lastName university')
      .sort({ updatedAt: -1 });
    
    res.status(HTTP_STATUS.OK).json({
      success: true,
      count: solutions.length,
      data: solutions
    });
  } catch (error: any) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message || 'Failed to fetch architect reviews'
    });
  }
};