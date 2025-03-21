import { Types } from 'mongoose';
import { Challenge, Solution } from '../models';
import { 
  IChallenge, 
  ISolution, 
  ChallengeStatus, 
  ChallengeDifficulty,
  ChallengeVisibility,
  SolutionStatus,
  HTTP_STATUS 
} from '../models/interfaces';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';

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
    try {
      // Validate company ID
      if (!Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid company ID format');
      }

      // Create new challenge with initial values
      const challenge = new Challenge({
        ...challengeData,
        company: companyId,
        status: ChallengeStatus.DRAFT,
        currentParticipants: 0,
        approvedSolutionsCount: 0
      });
      
      await challenge.save();
      logger.info(`Challenge created with ID: ${challenge._id} by company: ${companyId}`);
      
      return challenge;
    } catch (error) {
      logger.error('Error creating challenge:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create challenge');
    }
  }

  /**
   * Get a challenge by ID
   * @param challengeId - The ID of the challenge
   * @returns The challenge
   */
  async getChallengeById(challengeId: string): Promise<IChallenge> {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      const challenge = await Challenge.findById(challengeId).populate('company');
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found');
      }
      
      return challenge;
    } catch (error) {
      logger.error(`Error fetching challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenge');
    }
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
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      // Find challenge with company verification (security check)
      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found or you do not have permission to update it');
      }
      
      // Prevent status changes through this endpoint
      if (updateData.status && updateData.status !== challenge.status) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Challenge status cannot be updated through this endpoint');
      }
      
      // Prevent updating a challenge that's already closed or completed
      if ([ChallengeStatus.COMPLETED, ChallengeStatus.COMPLETED].includes(challenge.status as ChallengeStatus)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Cannot update a completed or cancelled challenge');
      }
      
      // Validate deadline if provided
      if (updateData.deadline && new Date(updateData.deadline) <= new Date()) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Deadline must be in the future');
      }
      
      // List of allowed fields that can be updated
      const allowedFields = [
        'title', 'description', 'requirements', 'resources', 'rewards',
        'deadline', 'difficulty', 'category', 'maxParticipants', 'tags',
        'maxApprovedSolutions', 'visibility', 'allowedInstitutions', 'isCompanyVisible'
      ];
      
      // Filter out fields that aren't allowed to be updated
      const filteredUpdateData = Object.fromEntries(
        Object.entries(updateData).filter(([key]) => allowedFields.includes(key))
      );
      
      // Update fields with validated data
      Object.assign(challenge, filteredUpdateData);
      
      await challenge.save();
      logger.info(`Challenge ${challengeId} updated by company ${companyId}`);
      
      return challenge;
    } catch (error) {
      logger.error(`Error updating challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update challenge');
    }
  }

  /**
   * Updates challenge statuses based on deadlines
   * This should be called by a scheduled job
   */
  async updateChallengeStatuses(): Promise<{
    updated: number;
    errors: number;
    details: Array<{ id: string; status: string }>;
  }> {
    try {
      logger.info('Starting automatic challenge status update job');

      // Find published challenges with passed deadlines
      const expiredChallenges = await Challenge.find({
        status: ChallengeStatus.ACTIVE,
        deadline: { $lt: new Date() }
      });
      
      logger.info(`Found ${expiredChallenges.length} expired challenges to update`);
      
      const results = {
        updated: 0,
        errors: 0,
        details: [] as Array<{ id: string; status: string }>
      };
      
      // Update status to indicate review phase
      for (const challenge of expiredChallenges) {
        try {
          challenge.status = ChallengeStatus.CLOSED;
          await challenge.save();
          
          results.updated++;
          results.details.push({ 
            id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id), 
            status: 'success' 
          });
          
          logger.info(`Challenge ${challenge._id} automatically closed due to passed deadline`);
          // Could trigger notifications here
        } catch (err) {
          results.errors++;
          results.details.push({ 
            id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id), 
            status: 'error' 
          });
          
          logger.error(`Failed to update status for challenge ${challenge._id}:`, err);
        }
      }
      
      logger.info(`Challenge status update job completed: ${results.updated} updated, ${results.errors} errors`);
      return results;
    } catch (error) {
      logger.error('Failed to update challenge statuses:', error);
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
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      // Find challenge with company verification (security check)
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
      
      // Validate required fields before publishing
      this.validateChallengeForPublication(challenge);
      
      challenge.status = ChallengeStatus.ACTIVE;
      challenge.publishedAt = new Date();
      await challenge.save();
      
      logger.info(`Challenge ${challengeId} published by company ${companyId}`);
      return challenge;
    } catch (error) {
      logger.error(`Error publishing challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to publish challenge');
    }
  }

  /**
   * Get challenges with filters
   * @param filters - Optional filters for challenges
   * @returns List of challenges with pagination metadata
   */
  async getChallenges(filters: {
    status?: ChallengeStatus;
    companyId?: string;
    category?: string | string[];
    difficulty?: ChallengeDifficulty;
    searchTerm?: string;
    page?: number;
    limit?: number;
    visibility?: ChallengeVisibility;
    startDate?: Date;
    endDate?: Date;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<{ 
    challenges: IChallenge[]; 
    total: number; 
    page: number; 
    limit: number;
    totalPages: number;
  }> {
    try {
      const { 
        status, 
        companyId, 
        category, 
        difficulty, 
        searchTerm,
        visibility,
        startDate,
        endDate,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        page = 1, 
        limit = 10 
      } = filters;
      
      const query: Record<string, any> = {};
      
      // Add filters to query
      if (status) {
        query.status = status;
      }
      
      if (companyId) {
        if (!Types.ObjectId.isValid(companyId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid company ID format');
        }
        query.company = new Types.ObjectId(companyId);
      }
      
      if (category) {
        if (Array.isArray(category)) {
          query.category = { $in: category };
        } else {
          query.category = category;
        }
      }
      
      if (difficulty) {
        query.difficulty = difficulty;
      }
      
      if (visibility) {
        query.visibility = visibility;
      }
      
      // Date range filtering
      if (startDate || endDate) {
        query.createdAt = {};
        
        if (startDate) {
          query.createdAt.$gte = new Date(startDate);
        }
        
        if (endDate) {
          query.createdAt.$lte = new Date(endDate);
        }
      }
      
      // Text search functionality
      if (searchTerm) {
        query.$or = [
          { title: { $regex: searchTerm, $options: 'i' } },
          { description: { $regex: searchTerm, $options: 'i' } },
          { tags: { $in: [new RegExp(searchTerm, 'i')] } }
        ];
      }
      
      // Pagination setup
      const pageNum = Math.max(1, page);
      const limitNum = Math.min(Math.max(1, limit), 50); // Cap at 50 items per page
      const skip = (pageNum - 1) * limitNum;
      
      // Sorting setup
      const sortOptions: Record<string, 1 | -1> = {};
      sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;
      
      // Execute queries in parallel for efficiency
      const [challenges, total] = await Promise.all([
        Challenge.find(query)
          .populate('company', 'companyName logo industry')
          .sort(sortOptions)
          .skip(skip)
          .limit(limitNum)
          .lean(),
        Challenge.countDocuments(query)
      ]);
      
      const totalPages = Math.ceil(total / limitNum);
      
      return {
        challenges,
        total,
        page: pageNum,
        limit: limitNum,
        totalPages
      };
    } catch (error) {
      logger.error('Error fetching challenges:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenges');
    }
  }

  /**
   * Close a challenge manually
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company closing the challenge
   * @returns The closed challenge
   */
  async closeChallenge(challengeId: string, companyId: string): Promise<IChallenge> {
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      // Find challenge with company verification (security check)
      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found or you do not have permission to close it');
      }
      
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw ApiError.badRequest('Only active challenges can be closed manually');
      }
      
      challenge.status = ChallengeStatus.CLOSED;
      challenge.completedAt = new Date();
      await challenge.save();
      
      logger.info(`Challenge ${challengeId} manually closed by company ${companyId}`);
      return challenge;
    } catch (error) {
      logger.error(`Error closing challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to close challenge');
    }
  }

  /**
   * Get challenge statistics
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company that owns the challenge
   * @returns Challenge statistics
   */
  async getChallengeStatistics(challengeId: string, companyId: string): Promise<{
    totalSolutions: number;
    solutionsByStatus: Record<string, number>;
    participationRate: number;
    averageRating: number;
    topTags: Array<{ tag: string; count: number }>;
  }> {
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      // Check challenge ownership
      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found or you do not have permission to view statistics');
      }
      
      // Get all solutions for this challenge
      const solutions = await Solution.find({ challenge: challengeId });
      
      // Calculate statistics
      const totalSolutions = solutions.length;
      
      // Count solutions by status
      const solutionsByStatus = solutions.reduce((acc, solution) => {
        const status = solution.status;
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      
      // Calculate participation rate if maxParticipants is set
      const participationRate = challenge.maxParticipants 
        ? (challenge.currentParticipants / challenge.maxParticipants) * 100 
        : challenge.currentParticipants;
      
      // Calculate average rating if there are any reviews
      let averageRating = 0;
      const ratedSolutions = solutions.filter(s => s.score && s.score > 0);
      if (ratedSolutions.length > 0) {
        averageRating = ratedSolutions.reduce((sum, s) => sum + (s.score || 0), 0) / ratedSolutions.length;
      }
      
      // Get top tags from solutions
      const tagCounts: Record<string, number> = {};
      solutions.forEach(solution => {
        if (solution.tags && Array.isArray(solution.tags)) {
          solution.tags.forEach(tag => {
            tagCounts[tag] = (tagCounts[tag] || 0) + 1;
          });
        }
      });
      
      const topTags = Object.entries(tagCounts)
        .map(([tag, count]) => ({ tag, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
      
      return {
        totalSolutions,
        solutionsByStatus,
        participationRate,
        averageRating,
        topTags
      };
    } catch (error) {
      logger.error(`Error fetching statistics for challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenge statistics');
    }
  }

  /**
   * Complete a challenge (final status after review phase)
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company completing the challenge
   * @returns The completed challenge
   */
  async completeChallenge(challengeId: string, companyId: string): Promise<IChallenge> {
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found or you do not have permission to complete it');
      }
      
      if (challenge.status !== ChallengeStatus.CLOSED) {
        throw ApiError.badRequest('Only closed challenges can be marked as completed');
      }
      
      // Check if all solutions have been reviewed
      const pendingSolutions = await Solution.countDocuments({
        challenge: challengeId,
        status: SolutionStatus.SUBMITTED
      });
      
      if (pendingSolutions > 0) {
        throw ApiError.badRequest(`There are still ${pendingSolutions} solutions pending review`);
      }
      
      challenge.status = ChallengeStatus.COMPLETED;
      challenge.completedAt = new Date();
      await challenge.save();
      
      logger.info(`Challenge ${challengeId} marked as completed by company ${companyId}`);
      return challenge;
    } catch (error) {
      logger.error(`Error completing challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to complete challenge');
    }
  }

  /**
   * Get all solutions for a particular challenge
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company requesting the solutions
   * @param filters - Optional filters for solutions
   * @returns A list of solutions with pagination metadata
   */
  async getChallengeSolutions(
    challengeId: string,
    companyId: string,
    filters: {
      status?: SolutionStatus;
      rating?: number;
      search?: string;
      page?: number;
      limit?: number;
    } = {}
  ): Promise<{
    solutions: ISolution[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid ID format');
      }

      // Verify that the company owns the challenge
      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found or you do not have permission to view solutions');
      }
      
      const { status, rating, search, page = 1, limit = 10 } = filters;
      
      const query: Record<string, any> = { challenge: challengeId };
      
      if (status) {
        query.status = status;
      }
      
      if (rating) {
        query.rating = { $gte: rating };
      }
      
      if (search) {
        query.$or = [
          { title: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      // Pagination setup
      const pageNum = Math.max(1, page);
      const limitNum = Math.min(Math.max(1, limit), 50);
      const skip = (pageNum - 1) * limitNum;
      
      // Execute queries in parallel
      const [solutions, total] = await Promise.all([
        Solution.find(query)
          .populate('student', 'firstName lastName email university')
          .populate('reviewedBy', 'firstName lastName specialization')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limitNum),
        Solution.countDocuments(query)
      ]);
      
      const totalPages = Math.ceil(total / limitNum);
      
      return {
        solutions,
        total,
        page: pageNum,
        limit: limitNum,
        totalPages
      };
    } catch (error) {
      logger.error(`Error fetching solutions for challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenge solutions');
    }
  }

  /**
   * Validate a challenge for publication
   * @param challenge - The challenge to validate
   * @throws ApiError if the challenge is invalid
   */
  private validateChallengeForPublication(challenge: IChallenge): void {
    const errors = [];
    
    if (!challenge.title || challenge.title.trim() === '') {
      errors.push('Challenge title is required');
    }
    
    if (!challenge.description || challenge.description.trim() === '') {
      errors.push('Challenge description is required');
    }
    
    if (!challenge.requirements || challenge.requirements.length === 0) {
      errors.push('At least one requirement is required');
    }
    
    if (!challenge.difficulty) {
      errors.push('Challenge difficulty is required');
    }
    
    if (!challenge.category || challenge.category.length === 0) {
      errors.push('At least one category is required');
    }
    
    if (!challenge.deadline) {
      errors.push('Challenge deadline is required');
    } else if (challenge.deadline <= new Date()) {
      errors.push('Challenge deadline must be in the future');
    }
    
    // If private, must have allowed institutions
    if (challenge.visibility === ChallengeVisibility.PRIVATE && 
        (!challenge.allowedInstitutions || challenge.allowedInstitutions.length === 0)) {
      errors.push('Private challenges must have at least one allowed institution');
    }
    
    if (errors.length > 0) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, `Challenge validation failed: ${errors.join(', ')}`);
    }
  }
}