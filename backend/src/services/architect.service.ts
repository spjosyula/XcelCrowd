import { Types } from 'mongoose';
import { ArchitectProfile, Solution, Challenge } from '../models';
import { IArchitectProfile, ISolution, SolutionStatus, ChallengeStatus, HTTP_STATUS } from '../models/interfaces';
import { ApiError } from '../utils/ApiError';

/**
 * Service for architect-related operations
 */
export class ArchitectService {
  /**
   * Get architect profile by user ID
   * @param userId - The ID of the user
   * @returns The architect profile
   */
  async getProfileByUserId(userId: string): Promise<IArchitectProfile> {
    const profile = await ArchitectProfile.findOne({ user: userId });
    if (!profile) {
      throw ApiError.notFound('Architect profile not found');
    }
    return profile;
  }

  /**
   * Create or update architect profile
   * @param userId - The ID of the user
   * @param profileData - The profile data to update
   * @returns The updated architect profile
   */
  async createOrUpdateProfile(userId: string, profileData: Partial<IArchitectProfile>): Promise<IArchitectProfile> {
    const profile = await ArchitectProfile.findOneAndUpdate(
      { user: userId },
      { ...profileData, user: userId },
      { new: true, upsert: true, runValidators: true }
    );
    return profile;
  }

  /**
   * Get pending solutions for review
   * @param filters - Optional filters for solutions
   * @returns List of solutions pending review
   */
  async getPendingSolutions(filters: {
    status?: SolutionStatus;
    challengeId?: string;
    studentId?: string;
    page?: number;
    limit?: number;
  }): Promise<{ solutions: ISolution[]; total: number; page: number; limit: number }> {
    const { status = SolutionStatus.SUBMITTED, challengeId, studentId, page = 1, limit = 10 } = filters;
    
    const query: Record<string, any> = { status };
    
    if (challengeId) {
      query.challenge = new Types.ObjectId(challengeId);
    }
    
    if (studentId) {
      query.student = new Types.ObjectId(studentId);
    }
    
    const skip = (page - 1) * limit;
    
    const [solutions, total] = await Promise.all([
      Solution.find(query)
        .populate('challenge', 'title description difficulty')
        .populate('student', 'firstName lastName university')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Solution.countDocuments(query)
    ]);
    
    return {
      solutions,
      total,
      page,
      limit
    };
  }

  /**
   * Get a specific solution by ID
   * @param solutionId - The ID of the solution
   * @returns The solution with populated references
   */
  async getSolutionById(solutionId: string): Promise<ISolution> {
    const solution = await Solution.findById(solutionId)
      .populate('challenge')
      .populate('student')
      .populate('reviewedBy');
      
    if (!solution) {
      throw ApiError.notFound('Solution not found');
    }
    
    return solution;
  }

  /**
   * Review a solution
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect reviewing
   * @param reviewData - The review data
   * @returns The updated solution
   */
  async reviewSolution(
    solutionId: string,
    architectId: string,
    reviewData: { status: SolutionStatus; feedback: string; score?: number }
  ): Promise<ISolution> {
    const solution = await Solution.findById(solutionId);
    
    if (!solution) {
      throw ApiError.notFound('Solution not found');
    }
    
    if (solution.status !== SolutionStatus.SUBMITTED && solution.status !== SolutionStatus.UNDER_REVIEW) {
      throw ApiError.badRequest('Solution has already been reviewed');
    }
    
    // If approving, check if challenge approval limit reached
    if (reviewData.status === SolutionStatus.APPROVED) {
      const challenge = await Challenge.findById(solution.challenge);
      if (!challenge) {
        throw ApiError.notFound('Challenge not found');
      }
      
      if (challenge.isApprovalLimitReached()) {
        throw ApiError.badRequest('Maximum number of approved solutions reached for this challenge');
      }
      
      // Increment the approved solutions count
      challenge.approvedSolutionsCount += 1;
      await challenge.save();
    }
    
    // Update solution with review data
    solution.status = reviewData.status;
    solution.feedback = reviewData.feedback;
    solution.reviewedBy = new Types.ObjectId(architectId);
    solution.reviewedAt = new Date();
    
    if (reviewData.score !== undefined) {
      solution.score = reviewData.score;
    }
    
    await solution.save();
    
    return solution.populate([
      { path: 'challenge' },
      { path: 'student' },
      { path: 'reviewedBy' }
    ]);
  }

  /**
   * Get architect dashboard statistics
   * @param architectId - The ID of the architect
   * @returns Dashboard statistics
   */
  async getDashboardStats(architectId: string): Promise<{
    totalReviewed: number;
    approved: number;
    rejected: number;
    pendingReview: number;
    recentActivity: ISolution[];
  }> {
    const [totalReviewed, approved, rejected, pendingReview, recentActivity] = await Promise.all([
      Solution.countDocuments({ reviewedBy: architectId }),
      Solution.countDocuments({ reviewedBy: architectId, status: SolutionStatus.APPROVED }),
      Solution.countDocuments({ reviewedBy: architectId, status: SolutionStatus.REJECTED }),
      Solution.countDocuments({ status: SolutionStatus.SUBMITTED }),
      Solution.find({ reviewedBy: architectId })
        .sort({ reviewedAt: -1 })
        .limit(5)
        .populate('challenge', 'title')
        .populate('student', 'firstName lastName')
    ]);
    
    return {
      totalReviewed,
      approved,
      rejected,
      pendingReview,
      recentActivity
    };
  }

  /**
   * Claim a solution for review
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect
   * @returns The updated solution
   */
  async claimSolutionForReview(solutionId: string, architectId: string): Promise<ISolution> {
    const solution = await Solution.findById(solutionId);
    
    if (!solution) {
      throw ApiError.notFound('Solution not found');
    }
    
    if (solution.status !== SolutionStatus.SUBMITTED) {
      throw ApiError.badRequest('Solution is not available for review');
    }
    
    solution.status = SolutionStatus.UNDER_REVIEW;
    await solution.save();
    
    return solution.populate([
      { path: 'challenge' },
      { path: 'student' }
    ]);
  }

  /**
   * Select solutions to forward to the company
   * @param challengeId - The ID of the challenge
   * @param solutionIds - Array of solution IDs to select
   * @param architectId - The ID of the architect making the selection
   * @returns The selected solutions
   */
  async selectSolutionsForCompany(
    challengeId: string,
    solutionIds: string[],
    architectId: string
  ): Promise<ISolution[]> {
    // Validate the challenge exists
    const challenge = await Challenge.findById(challengeId);
    if (!challenge) {
      throw ApiError.notFound('Challenge not found');
    }

    // Check if the architect is authorized to select solutions
    // This could be based on whether they've reviewed solutions for this challenge
    const hasReviewed = await Solution.exists({
      challenge: challengeId,
      reviewedBy: new Types.ObjectId(architectId)
    });
    
    if (!hasReviewed) {
      throw ApiError.forbidden('You are not authorized to select solutions for this challenge');
    }

    // Check if the number of solutions doesn't exceed the maximum allowed
    if (challenge.maxApprovedSolutions && solutionIds.length > challenge.maxApprovedSolutions) {
      throw ApiError.badRequest(`Cannot select more than ${challenge.maxApprovedSolutions} solutions for this challenge`);
    }

    // Verify all solutions are for this challenge and are approved
    const solutions = await Solution.find({
      _id: { $in: solutionIds.map(id => new Types.ObjectId(id)) },
      challenge: challengeId
    });

    if (solutions.length !== solutionIds.length) {
      throw ApiError.badRequest('One or more solution IDs are invalid or not part of this challenge');
    }

    // Check if all solutions are in APPROVED status
    const notApproved = solutions.some(sol => sol.status !== SolutionStatus.APPROVED);
    if (notApproved) {
      throw ApiError.badRequest('All solutions must be approved before selection');
    }

    // Update solutions to SELECTED status
    await Solution.updateMany(
      { _id: { $in: solutionIds.map(id => new Types.ObjectId(id)) } },
      { 
        $set: { 
          status: SolutionStatus.SELECTED,
          selectedAt: new Date(),
          selectedBy: new Types.ObjectId(architectId)
        }
      }
    );

    // Update challenge status if needed
    challenge.status = ChallengeStatus.COMPLETED;
    await challenge.save();

    // Return the selected solutions with populated fields
    return await Solution.find({ _id: { $in: solutionIds.map(id => new Types.ObjectId(id)) } })
      .populate([
        { path: 'challenge' },
        { path: 'student' },
        { path: 'reviewedBy' }
      ]);
  }
} 