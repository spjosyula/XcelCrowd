import mongoose, { Types } from 'mongoose';
import { Challenge, Solution } from '../models';
import {
  IChallenge,
  ISolution,
  ChallengeStatus,
  ChallengeDifficulty,
  ChallengeVisibility,
  SolutionStatus,
  HTTP_STATUS,
  UserRole
} from '../models/interfaces';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { BaseService } from './BaseService';

/**
 * Service for challenge-related operations
 */
export class ChallengeService extends BaseService {

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

      // OPTIMIZED: Limited fields in populated company
      const challenge = await Challenge.findById(challengeId)
        .populate('company', 'companyName industry location')
        .lean(); // OPTIMIZED: Added lean() for better performance

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
      if ([ChallengeStatus.COMPLETED, ChallengeStatus.CLOSED].includes(challenge.status as ChallengeStatus)) {
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

      return await this.withTransaction(async (session) => {
        const results = {
          updated: 0,
          errors: 0,
          details: [] as Array<{ id: string; status: string }>
        };

        // Find active challenges with passed deadlines
        const expiredSubmissionChallenges = await Challenge.find({
          status: ChallengeStatus.ACTIVE,
          deadline: { $lt: new Date() }
        });

        logger.info(`Found ${expiredSubmissionChallenges.length} expired submission challenges to update`);

        // Update submission deadline expired challenges
        for (const challenge of expiredSubmissionChallenges) {
          try {
            challenge.status = ChallengeStatus.CLOSED;
            await challenge.save({ session });

            results.updated++;
            results.details.push({
              id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id),
              status: 'success'
            });

            logger.info(`Challenge ${challenge._id} automatically closed due to passed submission deadline`);
          } catch (err) {
            results.errors++;
            results.details.push({
              id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id),
              status: 'error'
            });

            logger.error(`Failed to update status for challenge ${challenge._id}:`, err);
            throw err; // Rethrow to trigger transaction rollback
          }
        }

        // Find closed challenges with passed review deadlines
        const expiredReviewChallenges = await Challenge.find({
          status: ChallengeStatus.CLOSED,
          reviewDeadline: { $lt: new Date() },
          claimedBy: { $exists: true, $ne: null }
        });

        logger.info(`Found ${expiredReviewChallenges.length} expired review deadline challenges to update`);

        // Auto-complete challenges with expired review deadlines
        for (const challenge of expiredReviewChallenges) {
          try {
            challenge.status = ChallengeStatus.COMPLETED;
            challenge.completedAt = new Date();
            await challenge.save({ session });

            results.updated++;
            results.details.push({
              id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id),
              status: 'success-review'
            });

            logger.info(`Challenge ${challenge._id} automatically completed due to passed review deadline`);
          } catch (err) {
            results.errors++;
            results.details.push({
              id: challenge._id instanceof Types.ObjectId ? challenge._id.toString() : String(challenge._id),
              status: 'error-review'
            });

            logger.error(`Failed to auto-complete challenge ${challenge._id}:`, err);
            throw err; // Rethrow to trigger transaction rollback
          }
        }

        logger.info(`Challenge status update job completed: ${results.updated} updated, ${results.errors} errors`);
        return results;
      });
    } catch (error) {
      logger.error('Failed to update challenge statuses:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to update challenge statuses',
        true,
        'CHALLENGE_STATUS_UPDATE_ERROR'
      );
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

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);

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
        await challenge.save({ session });

        logger.info(`Challenge ${challengeId} published by company ${companyId}`);
        return challenge;
      });
    } catch (error) {
      logger.error(`Error publishing challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to publish challenge',
        true,
        'CHALLENGE_PUBLISH_ERROR'
      );
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
          // OPTIMIZED: Limited fields in populated company
          .populate('company', 'companyName logo')
          .sort(sortOptions)
          .skip(skip)
          .limit(limitNum)
          .lean(), // OPTIMIZED: Added lean() for better performance
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
  
      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);
  
        if (!challenge) {
          throw ApiError.notFound('Challenge not found or you do not have permission to close it');
        }
  
        if (challenge.status !== ChallengeStatus.ACTIVE) {
          throw ApiError.badRequest('Only active challenges can be closed manually');
        }
  
        challenge.status = ChallengeStatus.CLOSED;
        challenge.completedAt = new Date();
        await challenge.save({ session });
  
        logger.info(`Challenge ${challengeId} manually closed by company ${companyId}`);
        return challenge;
      });
    } catch (error) {
      logger.error(`Error closing challenge ${challengeId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to close challenge',
        true,
        'CHALLENGE_CLOSE_ERROR'
      );
    }
  }

  /**
 * Delete a challenge and its associated solutions
 * @param challengeId - The ID of the challenge to delete
 * @throws ApiError if challenge cannot be deleted
 */
  async deleteChallenge(challengeId: string): Promise<void> {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      // Find the challenge first to verify it exists
      const challenge = await Challenge.findById(challengeId);
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      await this.withTransaction(async (session) => {
        // Delete the challenge
        const deleteResult = await Challenge.findByIdAndDelete(challengeId).session(session);

        if (!deleteResult) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
        }

        // Delete all solutions for this challenge
        const solutionDeleteResult = await Solution.deleteMany({ challenge: challengeId }).session(session);

        logger.info(`Challenge ${challengeId} deleted with ${solutionDeleteResult.deletedCount} associated solutions`);
      });
    } catch (error) {
      logger.error(`Error deleting challenge ${challengeId}: ${error instanceof Error ? error.message : String(error)}`, { challengeId });
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete challenge');
    }
  }

  /**
 * Validate if a challenge can be deleted based on business rules
 * @param challengeId - The ID of the challenge to validate
 * @throws ApiError if challenge cannot be deleted
 */
  async validateChallengeCanBeDeleted(challengeId: string): Promise<void> {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      // Find the challenge
      const challenge = await Challenge.findById(challengeId);
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Business rule: Can't delete active/completed challenges with participants
      if (challenge.status !== ChallengeStatus.DRAFT && challenge.currentParticipants > 0) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'Cannot delete an active or completed challenge with participants'
        );
      }
    } catch (error) {
      logger.error(`Error validating if challenge ${challengeId} can be deleted:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to validate challenge deletion');
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
      if (!Types.ObjectId.isValid(challengeId) || (companyId !== 'admin' && !Types.ObjectId.isValid(companyId))) {
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
  
      return await this.withTransaction(async (session) => {
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);
  
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
        }).session(session);
  
        if (pendingSolutions > 0) {
          throw ApiError.badRequest(`There are still ${pendingSolutions} solutions pending review`);
        }
  
        challenge.status = ChallengeStatus.COMPLETED;
        challenge.completedAt = new Date();
        await challenge.save({ session });
  
        logger.info(`Challenge ${challengeId} marked as completed by company ${companyId}`);
        return challenge;
      });
    } catch (error) {
      logger.error(`Error completing challenge ${challengeId}: ${error instanceof Error ? error.message : String(error)}`, { challengeId, companyId });
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to complete challenge',
        true,
        'CHALLENGE_COMPLETION_ERROR'
      );
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
    if (!challenge.deadline) {
      errors.push('Challenge deadline is required');
    } else if (challenge.deadline <= new Date()) {
      errors.push('Challenge deadline must be in the future');
    }

    // Validate review deadline if provided
    if (challenge.reviewDeadline) {
      if (challenge.reviewDeadline <= challenge.deadline) {
        errors.push('Review deadline must be after submission deadline');
      }
      if (challenge.reviewDeadline <= new Date()) {
        errors.push('Review deadline must be in the future');
      }
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

  /**
 * Get challenge by ID with visibility controls
 */
  async getChallengeByIdWithVisibility(
    challengeId: string,
    userRole: UserRole,
    profileId?: string,
    studentProfile?: any
  ): Promise<any> {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      const challenge = await Challenge.findById(challengeId)
        .populate('company', '-user -__v');

      if (!challenge) {
        throw ApiError.notFound('Challenge not found');
      }

      // Check company ownership for company users
      const isCompanyOwner = userRole === UserRole.COMPANY &&
        profileId &&
        challenge.company &&
        typeof challenge.company !== 'string' &&
        challenge.company._id &&
        profileId === challenge.company._id.toString();

      // For private challenges, check institution access for students
      if (challenge.visibility === 'private' && userRole === UserRole.STUDENT) {
        if (!studentProfile?.university ||
          !challenge.allowedInstitutions?.includes(studentProfile.university)) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to view this private challenge'
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
          return restChallenge;
        }
      }

      return challengeObj;
    } catch (error) {
      logger.error(`Error fetching challenge ${challengeId} with visibility controls:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenge');
    }
  }

  private async getCompanyProfileForUser(userId: string): Promise<any> {
    try {
      // Import models here to avoid circular dependencies
      const { default: User } = await import('../models/User');
      const { default: CompanyProfile } = await import('../models/CompanyProfile');

      const user = await User.findById(userId);
      if (!user || user.role !== UserRole.COMPANY) {
        return null;
      }

      return await CompanyProfile.findOne({ user: userId });
    } catch (error) {
      logger.error(`Error getting company profile for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Get challenges with user-specific visibility
   */
  async getChallengesForUser(
    filters: {
      status?: string;
      difficulty?: string;
      category?: string | string[];
      searchTerm?: string;
      page?: number;
      limit?: number;
    },
    userId?: string,
    userRole?: UserRole,
    studentProfile?: any
  ): Promise<{
    challenges: any[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    try {
      // Build query filters
      const queryFilters: Record<string, any> = {};

      if (filters.difficulty) queryFilters.difficulty = filters.difficulty;
      if (filters.category) {
        queryFilters.category = {
          $in: Array.isArray(filters.category) ? filters.category : [filters.category]
        };
      }

      // Search in title and description
      if (filters.searchTerm) {
        const searchRegex = new RegExp(String(filters.searchTerm), 'i');
        queryFilters.$or = [
          { title: searchRegex },
          { description: searchRegex },
          { tags: searchRegex }
        ];
      }

      // Handle draft challenge visibility
      if (filters.status === 'draft') {
        // Only company users can see their own draft challenges
        if (userRole === UserRole.COMPANY && userId) {
          // Get the company profile ID for the current user
          const companyProfile = await this.getCompanyProfileForUser(userId);
          if (companyProfile) {
            queryFilters.status = ChallengeStatus.DRAFT;
            queryFilters.company = companyProfile._id;
          } else {
            // If company profile not found, return empty result
            return {
              challenges: [],
              total: 0,
              page: filters.page || 1,
              limit: filters.limit || 10,
              totalPages: 0
            };
          }
        } else if (userRole === UserRole.ADMIN) {
          // Admins can see all draft challenges
          queryFilters.status = ChallengeStatus.DRAFT;
        } else {
          // Non-company/admin users can't see draft challenges
          return {
            challenges: [],
            total: 0,
            page: filters.page || 1,
            limit: filters.limit || 10,
            totalPages: 0
          };
        }
      } else if (filters.status === 'all') {
        // For 'all' status requests:
        if (userRole === UserRole.COMPANY && userId) {
          // Companies can see all their own challenges plus active/closed/completed public challenges
          const companyProfile = await this.getCompanyProfileForUser(userId);
          if (companyProfile) {
            queryFilters.$or = [
              // Their own challenges of any status
              { company: companyProfile._id },
              // Active, closed, or completed public challenges
              {
                status: { $in: [ChallengeStatus.ACTIVE, ChallengeStatus.CLOSED, ChallengeStatus.COMPLETED] },
                visibility: 'public'
              }
            ];
          } else {
            // Only public non-draft challenges if company profile not found
            queryFilters.status = { $ne: ChallengeStatus.DRAFT };
          }
        } else if (userRole === UserRole.ADMIN) {
          // Admins can see all challenges
        } else {
          // Regular users only see non-draft challenges
          queryFilters.status = { $ne: ChallengeStatus.DRAFT };
        }
      } else if (filters.status) {
        // For specific non-draft status
        queryFilters.status = filters.status;
      } else {
        // Apply default filter if status not specified
        queryFilters.status = ChallengeStatus.ACTIVE;
      }

      // Apply visibility filters based on user role
      if (userRole === UserRole.STUDENT || !userRole) {
        // Initial visibility filter
        const visibilityFilter: Record<string, any> = { visibility: 'public' };

        // For authenticated students, also include private challenges they can access
        if (userRole === UserRole.STUDENT && userId && studentProfile?.university) {
          visibilityFilter.$or = [
            { visibility: 'public' },
            { visibility: 'anonymous' },
            {
              visibility: 'private',
              allowedInstitutions: { $in: [studentProfile.university] }
            }
          ];
        }

        queryFilters.$and = queryFilters.$and || [];
        queryFilters.$and.push(visibilityFilter);
      }

      // Pagination setup
      const page = Math.max(1, filters.page || 1);
      const limit = Math.min(Math.max(1, filters.limit || 10), 50);
      const skip = (page - 1) * limit;

      // Execute queries
      const [challenges, total] = await Promise.all([
        Challenge.find(queryFilters)
          .populate('company', '-user -__v')
          .select('-__v')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit),
        Challenge.countDocuments(queryFilters)
      ]);

      // Process challenges for visibility
      const processedChallenges = challenges.map(challenge => {
        const challengeObj = challenge.toObject();

        // For anonymous challenges, remove company data for non-company users
        if (challenge.visibility === 'anonymous' &&
          (userRole !== UserRole.COMPANY && userRole !== UserRole.ADMIN)) {
          if (challengeObj.company) {
            const { company, ...rest } = challengeObj;
            return rest;
          }
        }
        return challengeObj;
      });

      const totalPages = Math.ceil(total / limit);

      return {
        challenges: processedChallenges,
        total,
        page,
        limit,
        totalPages
      };
    } catch (error) {
      logger.error('Error fetching challenges with visibility filters:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve challenges');
    }
  }
}
// Create and export singleton instance
export const challengeService = new ChallengeService();