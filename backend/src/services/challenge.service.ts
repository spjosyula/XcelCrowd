import { Types } from 'mongoose';
import { Challenge, Solution } from '../models';
import { IChallenge, ChallengeStatus, ISolution, HTTP_STATUS } from '../models/interfaces';
import { ApiError } from '../utils/ApiError';

/**
 * Service for challenge-related operations
 */
export class ChallengeService {
  /**
   * Create a new challenge
   * @param companyId - The ID of the company creating the challenge
   * @param challengeData - The challenge data
   * @returns The created challenge
   */
  async createChallenge(companyId: string, challengeData: Partial<IChallenge>): Promise<IChallenge> {
    const challenge = new Challenge({
      ...challengeData,
      company: companyId,
      status: ChallengeStatus.DRAFT,
      currentParticipants: 0,
      approvedSolutionsCount: 0
    });
    
    await challenge.save();
    return challenge;
  }

  /**
   * Get a challenge by ID
   * @param challengeId - The ID of the challenge
   * @returns The challenge
   */
  async getChallengeById(challengeId: string): Promise<IChallenge> {
    const challenge = await Challenge.findById(challengeId).populate('company');
    
    if (!challenge) {
      throw ApiError.notFound('Challenge not found');
    }
    
    return challenge;
  }

  /**
   * Update a challenge
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company updating the challenge
   * @param updateData - The update data
   * @returns The updated challenge
   */
  async updateChallenge(
    challengeId: string,
    companyId: string,
    updateData: Partial<IChallenge>
  ): Promise<IChallenge> {
    const challenge = await Challenge.findOne({
      _id: challengeId,
      company: companyId
    });
    
    if (!challenge) {
      throw ApiError.notFound('Challenge not found or you do not have permission to update it');
    }
    
    // Update fields
    Object.assign(challenge, updateData);
    
    await challenge.save();
    return challenge;
  }

  /**
   * Updates challenge statuses based on deadlines
   * This should be called by a scheduled job
   */
  async updateChallengeStatuses(): Promise<void> {
    try {
      // Find published challenges with passed deadlines
      const expiredChallenges = await Challenge.find({
        status: ChallengeStatus.ACTIVE,
        deadline: { $lt: new Date() }
      });
      
      // Update status to indicate review phase
      for (const challenge of expiredChallenges) {
        challenge.status = ChallengeStatus.CLOSED;
        await challenge.save();
        
        // Could trigger notifications here
      }
    } catch (error) {
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update challenge statuses');
    }
  }

  /**
   * Publish a challenge
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company publishing the challenge
   * @returns The published challenge
   */
  async publishChallenge(challengeId: string, companyId: string): Promise<IChallenge> {
    const challenge = await Challenge.findOne({
      _id: challengeId,
      company: companyId
    });
    
    if (!challenge) {
      throw ApiError.notFound('Challenge not found or you do not have permission to publish it');
    }
    
    if (challenge.status !== ChallengeStatus.DRAFT) {
      throw ApiError.badRequest('Only draft challenges can be published');
    }
    
    challenge.status = ChallengeStatus.ACTIVE;
    await challenge.save();
    
    return challenge;
  }

  /**
   * Get challenges with filters
   * @param filters - Optional filters for challenges
   * @returns List of challenges
   */
  async getChallenges(filters: {
    status?: ChallengeStatus;
    companyId?: string;
    category?: string;
    difficulty?: string;
    page?: number;
    limit?: number;
  }): Promise<{ challenges: IChallenge[]; total: number; page: number; limit: number }> {
    const { status, companyId, category, difficulty, page = 1, limit = 10 } = filters;
    
    const query: Record<string, any> = {};
    
    if (status) {
      query.status = status;
    }
    
    if (companyId) {
      query.company = new Types.ObjectId(companyId);
    }
    
    if (category) {
      query.category = category;
    }
    
    if (difficulty) {
      query.difficulty = difficulty;
    }
    
    const skip = (page - 1) * limit;
    
    const [challenges, total] = await Promise.all([
      Challenge.find(query)
        .populate('company', 'companyName industry')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Challenge.countDocuments(query)
    ]);
    
    return {
      challenges,
      total,
      page,
      limit
    };
  }

  /**
   * Get solutions for a challenge
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company
   * @returns List of solutions
   */
  async getChallengeSolutions(
    challengeId: string,
    companyId: string
  ): Promise<ISolution[]> {
    // Verify the company owns the challenge
    const challenge = await Challenge.findOne({
      _id: challengeId,
      company: companyId
    });
    
    if (!challenge) {
      throw ApiError.notFound('Challenge not found or you do not have permission to view its solutions');
    }
    
    // Get all solutions for this challenge
    const solutions = await Solution.find({ challenge: challengeId })
      .populate('student', 'firstName lastName university')
      .populate('reviewedBy', 'firstName lastName specialization');
    
    return solutions;
  }
} 