import { Types } from 'mongoose';
import Challenge from '../models/Challenge';
import Solution from '../models/Solution';
import { BaseService } from './BaseService';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../models/interfaces';
import {
  IChallenge,
  ChallengeStatus,
  ChallengeDifficulty,
  ChallengeVisibility,
  UserRole,
  ISolution,
  SolutionStatus
} from '../models/interfaces';
import {
  PaginationResult,
  executePaginatedQuery,
  createPaginationResult
} from '../utils/paginationUtils';

export class ChallengeService extends BaseService {
  /**
   * Create a new challenge
   * @param companyId - The ID of the company creating the challenge
   * @param challengeData - The challenge data
   * @returns The created challenge
   */
  async createChallenge(companyId: string, challengeData: Partial<IChallenge>): Promise<IChallenge> {
    logger.info('[createChallenge] Creating new challenge', { companyId });
    
    try {
      // Validate company ID
      if (!Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid company ID format', 'INVALID_ID_FORMAT');
      }

      return await this.withTransaction(async (session) => {
        // Process autoPublish flag and set initial status
        const status = (challengeData as any).autoPublish === true ? 
          ChallengeStatus.ACTIVE : 
          ChallengeStatus.DRAFT;
          
        // Remove autoPublish flag from challenge data
        const { autoPublish, ...filteredData } = challengeData as any;

        // Create new challenge with initial values
        const challenge = new Challenge({
          ...filteredData,
          company: companyId,
          status,
          currentParticipants: 0,
          approvedSolutionsCount: 0
        });

        await challenge.save({ session });
        
        logger.info('[createChallenge] Challenge created successfully', {
          challengeId: challenge._id,
          companyId,
          status
        });

        return challenge;
      });
    } catch (error) {
      logger.error('[createChallenge] Failed to create challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal('Failed to create challenge', 'CHALLENGE_CREATION_ERROR');
    }
  }

  /**
   * Get a challenge by ID
   * @param challengeId - The ID of the challenge
   * @returns The challenge
   */
  async getChallengeById(challengeId: string): Promise<IChallenge> {
    logger.info('[getChallengeById] Fetching challenge', { challengeId });
    
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw ApiError.badRequest('Invalid challenge ID format', 'INVALID_ID_FORMAT');
      }

      // Limited fields in populated company for optimization
      const challenge = await Challenge.findById(challengeId)
        .populate('company', 'companyName industry location')
        .lean();
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
      }
      
      logger.info('[getChallengeById] Challenge retrieved successfully', { challengeId });
      return challenge;
    } catch (error) {
      logger.error('[getChallengeById] Failed to retrieve challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal('Failed to retrieve challenge', 'CHALLENGE_RETRIEVAL_ERROR');
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
    logger.info('[updateChallenge] Updating challenge', { 
      challengeId, 
      companyId,
      updateFields: Object.keys(updateData)
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);

        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to update it', 
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }

        // Prevent status changes through this endpoint
        if (updateData.status && updateData.status !== challenge.status) {
          throw ApiError.badRequest(
            'Status changes must be done through specific endpoints', 
            'STATUS_CHANGE_NOT_ALLOWED'
          );
        }

        // Prevent updating a challenge that's already closed or completed
        if ([ChallengeStatus.COMPLETED, ChallengeStatus.CLOSED].includes(challenge.status as ChallengeStatus)) {
          throw ApiError.badRequest(
            'Cannot update a closed or completed challenge', 
            'CHALLENGE_UPDATE_NOT_ALLOWED'
          );
        }

        // Validate deadline if provided
        if (updateData.deadline && new Date(updateData.deadline) <= new Date()) {
          throw ApiError.badRequest(
            'Deadline must be in the future', 
            'INVALID_DEADLINE'
          );
        }

        // List of allowed fields that can be updated
        const allowedFields = [
          'title', 'description', 'requirements', 'resources', 'rewards',
          'deadline', 'difficulty', 'category', 'maxParticipants', 
          'tags', 'maxApprovedSolutions', 'visibility', 'allowedInstitutions', 
          'isCompanyVisible'
        ];

        // Filter out fields that aren't allowed to be updated
        const filteredUpdateData = Object.fromEntries(
          Object.entries(updateData).filter(([key]) => allowedFields.includes(key))
        );

        // Update fields with validated data
        Object.assign(challenge, filteredUpdateData);

        await challenge.save({ session });
        
        logger.info('[updateChallenge] Challenge updated successfully', { 
          challengeId, 
          companyId 
        });

        return challenge;
      });
    } catch (error) {
      logger.error('[updateChallenge] Failed to update challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to update challenge', 
        'CHALLENGE_UPDATE_ERROR'
      );
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
    logger.info('[updateChallengeStatuses] Starting automatic challenge status update job');
    
    try {
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
        }).session(session);

        logger.info('[updateChallengeStatuses] Found expired submission challenges', { 
          count: expiredSubmissionChallenges.length 
        });

        // Update submission deadline expired challenges
        for (const challenge of expiredSubmissionChallenges) {
          try {
            challenge.status = ChallengeStatus.CLOSED;
            await challenge.save({ session });
            
            results.updated++;
            results.details.push({ 
              id: (challenge as IChallenge & { _id: Types.ObjectId })._id.toString(), 
              status: ChallengeStatus.CLOSED 
            });
          } catch (err) {
            results.errors++;
            logger.error('[updateChallengeStatuses] Failed to update challenge status', {
              error: err instanceof Error ? err.message : String(err),
              challengeId: challenge._id
            });
          }
        }

        logger.info('[updateChallengeStatuses] Challenge status update job completed', { 
          updated: results.updated, 
          errors: results.errors 
        });
        
        return results;
      });
    } catch (error) {
      logger.error('[updateChallengeStatuses] Fatal error in status update job', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to update challenge statuses',
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
    logger.info('[publishChallenge] Publishing challenge', { 
      challengeId, 
      companyId 
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);

        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to publish it',
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }

        if (challenge.status !== ChallengeStatus.DRAFT) {
          throw ApiError.badRequest(
            'Only draft challenges can be published',
            'CHALLENGE_NOT_DRAFT'
          );
        }

        // Validate required fields before publishing
        this.validateChallengeForPublication(challenge);

        challenge.status = ChallengeStatus.ACTIVE;
        challenge.publishedAt = new Date();
        await challenge.save({ session });

        logger.info('[publishChallenge] Challenge published successfully', { 
          challengeId, 
          companyId 
        });
        
        return challenge;
      });
    } catch (error) {
      logger.error('[publishChallenge] Failed to publish challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to publish challenge',
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
  }): Promise<PaginationResult<IChallenge>> {
    logger.info('[getChallenges] Fetching challenges with filters', { 
      filters: { ...filters, limit: filters.limit || 10, page: filters.page || 1 } 
    });
    
    try {
      // Build query filters
      const queryFilters: Record<string, any> = {};

      if (filters.status) {
        queryFilters.status = filters.status;
      }

      if (filters.companyId) {
        if (!Types.ObjectId.isValid(filters.companyId)) {
          throw ApiError.badRequest('Invalid company ID format', 'INVALID_ID_FORMAT');
        }
        queryFilters.company = new Types.ObjectId(filters.companyId);
      }

      if (filters.category) {
        if (Array.isArray(filters.category)) {
          queryFilters.category = { $in: filters.category };
        } else {
          queryFilters.category = filters.category;
        }
      }

      if (filters.difficulty) {
        queryFilters.difficulty = filters.difficulty;
      }

      if (filters.visibility) {
        queryFilters.visibility = filters.visibility;
      }

      // Date range filtering
      if (filters.startDate || filters.endDate) {
        queryFilters.createdAt = {};

        if (filters.startDate) {
          queryFilters.createdAt.$gte = new Date(filters.startDate);
        }

        if (filters.endDate) {
          queryFilters.createdAt.$lte = new Date(filters.endDate);
        }
      }

      // Text search functionality
      if (filters.searchTerm) {
        queryFilters.$or = [
          { title: { $regex: filters.searchTerm, $options: 'i' } },
          { description: { $regex: filters.searchTerm, $options: 'i' } },
          { tags: { $in: [new RegExp(filters.searchTerm, 'i')] } }
        ];
      }

      // Use pagination utilities for standardized pagination
      return await executePaginatedQuery<IChallenge>(
        Challenge,
        queryFilters,
        {
          page: filters.page || 1,
          limit: filters.limit || 10,
          sortBy: filters.sortBy || 'createdAt',
          sortOrder: filters.sortOrder || 'desc',
          maxLimit: 50 // Set max items per page
        },
        // Query modifier for populating relations and other operations
        (query) => query.populate('company', 'companyName logo').lean()
      );
    } catch (error) {
      logger.error('[getChallenges] Failed to retrieve challenges', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        filters
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to retrieve challenges',
        'CHALLENGE_RETRIEVAL_ERROR'
      );
    }
  }

  /**
   * Close a challenge manually
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company closing the challenge
   * @returns The closed challenge
   */
  async closeChallenge(challengeId: string, companyId: string): Promise<IChallenge> {
    logger.info('[closeChallenge] Closing challenge manually', { 
      challengeId, 
      companyId 
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }
  
      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);
  
        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to close it',
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }
  
        if (challenge.status !== ChallengeStatus.ACTIVE) {
          throw ApiError.badRequest(
            'Only active challenges can be closed manually',
            'CHALLENGE_NOT_ACTIVE'
          );
        }
  
        challenge.status = ChallengeStatus.CLOSED;
        challenge.completedAt = new Date();
        await challenge.save({ session });
  
        logger.info('[closeChallenge] Challenge closed successfully', { 
          challengeId, 
          companyId 
        });
        
        return challenge;
      });
    } catch (error) {
      logger.error('[closeChallenge] Failed to close challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to close challenge',
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
    logger.info('[deleteChallenge] Deleting challenge and associated solutions', { 
      challengeId 
    });
    
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw ApiError.badRequest('Invalid challenge ID format', 'INVALID_ID_FORMAT');
      }

      // Find the challenge first to verify it exists
      const challenge = await Challenge.findById(challengeId);
      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
      }

      await this.withTransaction(async (session) => {
        // Delete the challenge
        const deleteResult = await Challenge.findByIdAndDelete(challengeId).session(session);

        if (!deleteResult) {
          throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
        }

        // Delete all solutions for this challenge
        const solutionDeleteResult = await Solution.deleteMany({ 
          challenge: challengeId 
        }).session(session);

        logger.info('[deleteChallenge] Challenge and solutions deleted successfully', { 
          challengeId, 
          deletedSolutions: solutionDeleteResult.deletedCount 
        });
      });
    } catch (error) {
      logger.error('[deleteChallenge] Failed to delete challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to delete challenge',
        'CHALLENGE_DELETION_ERROR'
      );
    }
  }

  /**
   * Validate if a challenge can be deleted based on business rules
   * @param challengeId - The ID of the challenge to validate
   * @throws ApiError if challenge cannot be deleted
   */
  async validateChallengeCanBeDeleted(challengeId: string): Promise<void> {
    logger.info('[validateChallengeCanBeDeleted] Validating if challenge can be deleted', { 
      challengeId 
    });
    
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw ApiError.badRequest('Invalid challenge ID format', 'INVALID_ID_FORMAT');
      }

      // Find the challenge
      const challenge = await Challenge.findById(challengeId);
      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
      }

      // Business rule: Can't delete active/completed challenges with participants
      if (challenge.status !== ChallengeStatus.DRAFT && challenge.currentParticipants > 0) {
        throw ApiError.forbidden(
          'Cannot delete an active or completed challenge with participants',
          'CHALLENGE_DELETION_FORBIDDEN'
        );
      }
      
      logger.info('[validateChallengeCanBeDeleted] Challenge can be deleted', { 
        challengeId 
      });
    } catch (error) {
      logger.error('[validateChallengeCanBeDeleted] Failed to validate challenge deletion', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to validate challenge deletion',
        'CHALLENGE_VALIDATION_ERROR'
      );
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
    logger.info('[getChallengeStatistics] Fetching challenge statistics', { 
      challengeId, 
      companyId 
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || (companyId !== 'admin' && !Types.ObjectId.isValid(companyId))) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }

      // Check challenge ownership
      const challenge = await Challenge.findOne({
        _id: challengeId,
        ...(companyId !== 'admin' ? { company: companyId } : {})
      });

      if (!challenge) {
        throw ApiError.notFound(
          'Challenge not found or you do not have permission to view statistics',
          'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
        );
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

      const statistics = {
        totalSolutions,
        solutionsByStatus,
        participationRate,
        averageRating,
        topTags
      };
      
      logger.info('[getChallengeStatistics] Statistics retrieved successfully', { 
        challengeId, 
        totalSolutions 
      });
      
      return statistics;
    } catch (error) {
      logger.error('[getChallengeStatistics] Failed to retrieve challenge statistics', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to retrieve challenge statistics',
        'CHALLENGE_STATISTICS_ERROR'
      );
    }
  }

  /**
   * Complete a challenge (final status after review phase)
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company completing the challenge
   * @returns The completed challenge
   */
  async completeChallenge(challengeId: string, companyId: string): Promise<IChallenge> {
    logger.info('[completeChallenge] Completing challenge', { 
      challengeId, 
      companyId 
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }
  
      return await this.withTransaction(async (session) => {
        const challenge = await Challenge.findOne({
          _id: challengeId,
          company: companyId
        }).session(session);
  
        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to complete it',
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }
  
        if (challenge.status !== ChallengeStatus.CLOSED) {
          throw ApiError.badRequest(
            'Only closed challenges can be marked as completed',
            'CHALLENGE_NOT_CLOSED'
          );
        }
  
        // Check if all solutions have been reviewed
        const pendingSolutions = await Solution.countDocuments({
          challenge: challengeId,
          status: SolutionStatus.SUBMITTED
        }).session(session);
  
        if (pendingSolutions > 0) {
          throw ApiError.badRequest(
            `There are still ${pendingSolutions} solutions pending review`,
            'PENDING_SOLUTIONS_EXIST'
          );
        }
  
        challenge.status = ChallengeStatus.COMPLETED;
        challenge.completedAt = new Date();
        await challenge.save({ session });
  
        logger.info('[completeChallenge] Challenge marked as completed', { 
          challengeId, 
          companyId 
        });
        
        return challenge;
      });
    } catch (error) {
      logger.error('[completeChallenge] Failed to complete challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to complete challenge',
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
  ): Promise<PaginationResult<ISolution>> {
    logger.info('[getChallengeSolutions] Fetching solutions for challenge', { 
      challengeId, 
      companyId, 
      filters 
    });
    
    try {
      // Validate IDs
      if (!Types.ObjectId.isValid(challengeId) || !Types.ObjectId.isValid(companyId)) {
        throw ApiError.badRequest('Invalid ID format', 'INVALID_ID_FORMAT');
      }

      // Verify that the company owns the challenge
      const challenge = await Challenge.findOne({
        _id: challengeId,
        company: companyId
      });

      if (!challenge) {
        throw ApiError.notFound(
          'Challenge not found or you do not have permission to view solutions',
          'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
        );
      }

      const { status, rating, search } = filters;

      const queryFilters: Record<string, any> = { challenge: challengeId };

      if (status) {
        queryFilters.status = status;
      }

      if (rating) {
        queryFilters.rating = { $gte: rating };
      }

      if (search) {
        queryFilters.$or = [
          { title: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }

      // Use standardized pagination
      return await executePaginatedQuery<ISolution>(
        Solution,
        queryFilters,
        {
          page: filters.page || 1,
          limit: filters.limit || 10,
          sortBy: 'createdAt',
          sortOrder: 'desc',
          maxLimit: 50
        },
        // Query modifier for populating relations
        (query) => query
          .populate('student', 'firstName lastName email university')
          .populate('reviewedBy', 'firstName lastName specialization')
      );
    } catch (error) {
      logger.error('[getChallengeSolutions] Failed to retrieve solutions', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to retrieve challenge solutions',
        'CHALLENGE_SOLUTIONS_ERROR'
      );
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
    logger.info('[getChallengeByIdWithVisibility] Fetching challenge with visibility controls', { 
      challengeId, 
      userRole,
      profileId: profileId || 'undefined'
    });
    
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw ApiError.badRequest('Invalid challenge ID format', 'INVALID_ID_FORMAT');
      }

      const challenge = await Challenge.findById(challengeId)
        .populate('company', '-user -__v');

      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
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
          logger.warn('[getChallengeByIdWithVisibility] Student access denied to private challenge', {
            challengeId,
            studentUniversity: studentProfile?.university,
            allowedInstitutions: challenge.allowedInstitutions
          });
          
          throw ApiError.forbidden(
            'You do not have permission to view this private challenge',
            'PRIVATE_CHALLENGE_ACCESS_DENIED'
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
          
          logger.info('[getChallengeByIdWithVisibility] Removed company data for anonymous challenge', { 
            challengeId 
          });
          
          return restChallenge;
        }
      }

      logger.info('[getChallengeByIdWithVisibility] Challenge retrieved successfully', { 
        challengeId 
      });
      
      return challengeObj;
    } catch (error) {
      logger.error('[getChallengeByIdWithVisibility] Failed to retrieve challenge with visibility controls', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        userRole
      });
      
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to retrieve challenge',
        'CHALLENGE_RETRIEVAL_ERROR'
      );
    }
  }

  /**
   * Get the company profile associated with a user ID
   * @private
   */
  private async getCompanyProfileForUser(userId: string): Promise<any> {
    logger.info('[getCompanyProfileForUser] Fetching company profile for user', { 
      userId 
    });
    
    try {
      // Import models here to avoid circular dependencies
      const { default: User } = await import('../models/User');
      const { default: CompanyProfile } = await import('../models/CompanyProfile');

      const user = await User.findById(userId);
      if (!user || user.role !== UserRole.COMPANY) {
        logger.info('[getCompanyProfileForUser] User is not a company user', { 
          userId, 
          userRole: user?.role 
        });
        return null;
      }

      const profile = await CompanyProfile.findOne({ user: userId });
      logger.info('[getCompanyProfileForUser] Company profile fetched', { 
        userId, 
        profileFound: !!profile 
      });
      
      return profile;
    } catch (error) {
      logger.error('[getCompanyProfileForUser] Failed to get company profile', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        userId
      });
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
  ): Promise<PaginationResult<any>> {
    try {
      logger.info('[getChallengesForUser] Fetching challenges with user-specific visibility', { 
        userId, 
        userRole,
        filters 
      });

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
            return createPaginationResult([], 0, filters.page || 1, filters.limit || 10);
          }
        } else if (userRole === UserRole.ADMIN) {
          // Admins can see all draft challenges
          queryFilters.status = ChallengeStatus.DRAFT;
        } else {
          // Non-company/admin users can't see draft challenges
          return createPaginationResult([], 0, filters.page || 1, filters.limit || 10);
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

      // Use pagination utilities for standardized handling
      const result = await executePaginatedQuery(
        Challenge,
        queryFilters,
        {
          page: filters.page || 1,
          limit: filters.limit || 10,
          sortBy: 'createdAt',
          sortOrder: 'desc'
        },
        (query) => query.populate('company', '-user -__v').lean()
      );
      
      // Process visibility after query execution
      result.data = this.processVisibility(userRole, result.data);
      return result;
    } catch (error) {
      logger.error('[getChallengesForUser] Failed to retrieve challenges with visibility filters', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        userId,
        userRole
      });
      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to retrieve challenges',
        'CHALLENGE_RETRIEVAL_ERROR'
      );
    }
  }

  /**
   * Process visibility settings for challenge data
   * @private
   */
  private processVisibility(userRole: UserRole | undefined, challenges: any[]): any[] {
    if (!challenges) return [];
    
    return challenges.map(challenge => {
      const challengeObj = typeof challenge.toObject === 'function' 
        ? challenge.toObject() 
        : challenge;

      // For anonymous challenges, remove company data for non-company/admin users
      if (challengeObj.visibility === 'anonymous' &&
        (userRole !== UserRole.COMPANY && userRole !== UserRole.ADMIN)) {
        if (challengeObj.company) {
          const { company, ...rest } = challengeObj;
          return rest;
        }
      }
      return challengeObj;
    });
  }

  /**
   * Validate a challenge for publication
   * @param challenge - The challenge to validate
   * @throws ApiError if the challenge is invalid
   */
  private validateChallengeForPublication(challenge: IChallenge): void {
    logger.info('[validateChallengeForPublication] Validating challenge for publication', { 
      challengeId: challenge._id 
    });
    
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
      logger.warn('[validateChallengeForPublication] Challenge validation failed', {
        challengeId: challenge._id,
        errors
      });
      
      throw ApiError.badRequest(
        `Challenge validation failed: ${errors.join(', ')}`,
        'CHALLENGE_VALIDATION_FAILED'
      );
    }
    
    logger.info('[validateChallengeForPublication] Challenge passed validation', { 
      challengeId: challenge._id 
    });
  }

  /**
   * Helper method for challenge owner authorization
   * @param userIdOrProfileId - The ID of the user or profile performing the action
   * @param userRole - The role of the user
   * @param challengeId - The ID of the challenge
   * @param action - The action being performed
   * @returns The challenge if authorization succeeds
   */
  async authorizeChallengeOwner(
    userIdOrProfileId: string,
    userRole: UserRole,
    challengeId: string,
    action: string
  ): Promise<IChallenge> {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw ApiError.badRequest(`Invalid challenge ID format: ${challengeId}`, 'INVALID_ID_FORMAT');
      }

      // Get the challenge
      const challenge = await this.getChallengeById(challengeId);
      
      if (!challenge) {
        throw ApiError.notFound(
          `Challenge not found with id: ${challengeId}`,
          'CHALLENGE_NOT_FOUND'
        );
      }

      // Verify ownership (except for admin)
      if (userRole !== UserRole.ADMIN) {
        if (userRole !== UserRole.COMPANY) {
          throw ApiError.forbidden(
            `Only companies and admins can ${action} challenges`,
            'INSUFFICIENT_ROLE'
          );
        }

        // For company users, verify they own the challenge
        if (challenge.company.toString() !== userIdOrProfileId) {
          throw ApiError.forbidden(
            `You do not have permission to ${action} this challenge`,
            'NOT_CHALLENGE_OWNER'
          );
        }
      }

      // Log successful authorization
      logger.info('[authorizeChallengeOwner] Challenge access authorized', {
        challengeId,
        action,
        userIdOrProfileId,
        role: userRole
      });

      return challenge;
    } catch (error) {
      // Re-throw API errors
      if (error instanceof ApiError) throw error;
      
      // Convert and log other errors
      logger.error('[authorizeChallengeOwner] Error', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        userIdOrProfileId,
        userRole
      });
      
      throw ApiError.internal(
        'Error while authorizing access to challenge',
        'CHALLENGE_AUTH_ERROR'
      );
    }
  }
}

export const challengeService = new ChallengeService();