import { Types } from 'mongoose';
import Challenge from '../models/Challenge';
import Solution from '../models/Solution';
import { BaseService } from './BaseService';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/api.error';
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
import { MongoSanitizer } from '../utils/mongo.sanitize';

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
      // Validate company ID using MongoSanitizer to prevent NoSQL injection
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(
        companyId, 
        'company', 
        { errorStatus: 400, additionalContext: 'When creating a challenge' }
      );

      // Sanitize challenge data
      const sanitizedData = this.sanitizeChallengeData(challengeData);

      return await this.withTransaction(async (session) => {
        // Process autoPublish flag and set initial status
        const status = (challengeData as any).autoPublish === true ?
          ChallengeStatus.ACTIVE :
          ChallengeStatus.DRAFT;

        // Remove autoPublish flag from challenge data
        const { autoPublish, ...filteredData } = sanitizedData as any;

        // Create new challenge with initial values
        const challenge = new Challenge({
          ...filteredData,
          company: sanitizedCompanyId,
          status,
          currentParticipants: 0,
          approvedSolutionsCount: 0
        });

        await challenge.save({ session });

        logger.info('[createChallenge] Challenge created successfully', {
          challengeId: challenge._id,
          companyId: sanitizedCompanyId,
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
   * Sanitizes challenge data to prevent NoSQL injection
   * @param data - The raw challenge data to sanitize
   * @returns Sanitized challenge data
   */
  private sanitizeChallengeData(data: Partial<IChallenge>): Partial<IChallenge> {
    if (!data || typeof data !== 'object') {
      throw ApiError.badRequest('Invalid challenge data', 'INVALID_CHALLENGE_DATA');
    }

    const sanitized: Partial<IChallenge> = {};

    // Sanitize string fields
    if (data.title !== undefined) {
      sanitized.title = MongoSanitizer.sanitizeString(data.title, {
        fieldName: 'Challenge title',
        maxLength: 100
      });
    }

    if (data.description !== undefined) {
      sanitized.description = MongoSanitizer.sanitizeString(data.description, {
        fieldName: 'Challenge description',
        maxLength: 5000
      });
    }

    // Sanitize any direct MongoDB ObjectId references
    if (data.company !== undefined && typeof data.company === 'string') {
      try {
        sanitized.company = MongoSanitizer.sanitizeObjectId(data.company, 'company');
      } catch (error) {
        logger.warn('[sanitizeChallengeData] Invalid company ID provided', {
          companyId: data.company,
          error: error instanceof Error ? error.message : String(error)
        });
        // Don't include invalid IDs in sanitized data
      }
    }

    // Sanitize array fields
    if (data.requirements && Array.isArray(data.requirements)) {
      sanitized.requirements = data.requirements.map(item => 
        MongoSanitizer.sanitizeString(item, {
          fieldName: 'Requirement',
          maxLength: 500
        })
      );
    }

    if (data.resources && Array.isArray(data.resources)) {
      sanitized.resources = data.resources.map(item => 
        MongoSanitizer.sanitizeString(item, {
          fieldName: 'Resource',
          maxLength: 1000
        })
      );
    }

    if (data.category && Array.isArray(data.category)) {
      sanitized.category = data.category.map(item => 
        MongoSanitizer.sanitizeString(item, {
          fieldName: 'Category',
          maxLength: 100
        })
      );
    }

    if (data.tags && Array.isArray(data.tags)) {
      sanitized.tags = data.tags.map(item => 
        MongoSanitizer.sanitizeString(item, {
          fieldName: 'Tag',
          maxLength: 50
        })
      );
    }

    if (data.allowedInstitutions && Array.isArray(data.allowedInstitutions)) {
      sanitized.allowedInstitutions = data.allowedInstitutions.map(item => 
        MongoSanitizer.sanitizeString(item, {
          fieldName: 'Institution',
          maxLength: 200
        })
      );
    }

    // Sanitize rewards field
    if (data.rewards !== undefined) {
      sanitized.rewards = MongoSanitizer.sanitizeString(data.rewards, {
        fieldName: 'Rewards',
        maxLength: 1000,
        required: false
      });
    }

    // Sanitize enum values
    if (data.difficulty !== undefined) {
      if (!Object.values(ChallengeDifficulty).includes(data.difficulty as ChallengeDifficulty)) {
        throw ApiError.badRequest(
          `Invalid difficulty value. Allowed values: ${Object.values(ChallengeDifficulty).join(', ')}`,
          'INVALID_DIFFICULTY'
        );
      }
      sanitized.difficulty = data.difficulty;
    }

    if (data.status !== undefined) {
      if (!Object.values(ChallengeStatus).includes(data.status as ChallengeStatus)) {
        throw ApiError.badRequest(
          `Invalid status value. Allowed values: ${Object.values(ChallengeStatus).join(', ')}`,
          'INVALID_STATUS'
        );
      }
      sanitized.status = data.status;
    }

    if (data.visibility !== undefined) {
      if (!Object.values(ChallengeVisibility).includes(data.visibility as ChallengeVisibility)) {
        throw ApiError.badRequest(
          `Invalid visibility value. Allowed values: ${Object.values(ChallengeVisibility).join(', ')}`,
          'INVALID_VISIBILITY'
        );
      }
      sanitized.visibility = data.visibility;
    }

    // Sanitize numeric fields
    if (data.maxParticipants !== undefined) {
      if (typeof data.maxParticipants !== 'number' || 
          data.maxParticipants < 1 || 
          data.maxParticipants > 10000) {
        throw ApiError.badRequest(
          'Maximum participants must be a positive number between 1 and 10000',
          'INVALID_MAX_PARTICIPANTS'
        );
      }
      sanitized.maxParticipants = data.maxParticipants;
    }

    if (data.maxApprovedSolutions !== undefined) {
      if (typeof data.maxApprovedSolutions !== 'number' || 
          data.maxApprovedSolutions < 1 || 
          data.maxApprovedSolutions > 1000) {
        throw ApiError.badRequest(
          'Maximum approved solutions must be a positive number between 1 and 1000',
          'INVALID_MAX_APPROVED_SOLUTIONS'
        );
      }
      sanitized.maxApprovedSolutions = data.maxApprovedSolutions;
    }

    // Sanitize boolean fields
    if (data.isCompanyVisible !== undefined) {
      sanitized.isCompanyVisible = Boolean(data.isCompanyVisible);
    }

    // Sanitize dates
    if (data.deadline !== undefined) {
      const deadlineDate = new Date(data.deadline);
      if (isNaN(deadlineDate.getTime())) {
        throw ApiError.badRequest('Invalid deadline date format', 'INVALID_DEADLINE_FORMAT');
      }
      sanitized.deadline = deadlineDate;
    }

    // Include any additional autoPublish flag if present
    if ((data as any).autoPublish !== undefined) {
      (sanitized as any).autoPublish = Boolean((data as any).autoPublish);
    }

    return sanitized;
  }

  /**
   * Get a challenge by ID
   * @param challengeId - The ID of the challenge
   * @returns The challenge
   */
  async getChallengeById(challengeId: string): Promise<IChallenge> {
    logger.info('[getChallengeById] Fetching challenge', { challengeId });

    try {
      // Validate challenge ID using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When fetching challenge' }
      );

      // Limited fields in populated company for optimization
      // Use $eq operator to prevent NoSQL injection
      const challenge = await Challenge.findById({ $eq: sanitizedChallengeId })
        .populate('company', 'companyName industry location')
        .lean();

      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
      }

      logger.info('[getChallengeById] Challenge retrieved successfully', { challengeId: sanitizedChallengeId });
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
    if (!updateData || Object.keys(updateData).length === 0) {
      throw ApiError.badRequest(
        'No update data provided',
        'EMPTY_UPDATE_DATA'
      );
    }
    logger.info('[updateChallenge] Updating challenge', {
      challengeId,
      companyId,
      updateFields: Object.keys(updateData)
    });

    try {
      // Validate IDs using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When updating challenge' }
      );
      
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(
        companyId, 
        'company', 
        { errorStatus: 400, additionalContext: 'When updating challenge' }
      );

      // Sanitize update data
      const sanitizedUpdateData = this.sanitizeChallengeData(updateData);

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        // Use $eq operator to prevent NoSQL injection
        const challenge = await Challenge.findOne({
          _id: { $eq: sanitizedChallengeId },
          company: { $eq: sanitizedCompanyId }
        }).session(session);

        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to update it',
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }

        // Prevent status changes through this endpoint
        if (sanitizedUpdateData.status && sanitizedUpdateData.status !== challenge.status) {
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

        // Add this validation block
        if (sanitizedUpdateData.visibility === ChallengeVisibility.PRIVATE &&
          (!sanitizedUpdateData.allowedInstitutions || sanitizedUpdateData.allowedInstitutions.length === 0)) {
          // If challenge was already private, keep its existing institutions
          if (challenge.visibility !== ChallengeVisibility.PRIVATE) {
            throw ApiError.badRequest(
              'Private challenges must have at least one allowed institution',
              'INVALID_VISIBILITY_SETTINGS'
            );
          }
        }

        // Validate deadline if provided
        if (sanitizedUpdateData.deadline && new Date(sanitizedUpdateData.deadline) <= new Date()) {
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
        const filteredUpdateData: Partial<IChallenge> = {};
        
        for (const field of allowedFields) {
          if (field in sanitizedUpdateData) {
            filteredUpdateData[field as keyof IChallenge] = 
              sanitizedUpdateData[field as keyof IChallenge];
          }
        }

        // Safely update allowed fields using MongoSanitizer
        const safeUpdateOps = MongoSanitizer.sanitizeUpdateOperations(
          { $set: filteredUpdateData },
          allowedFields
        );

        // Update using findOneAndUpdate with sanitized operations
        const updatedChallenge = await Challenge.findOneAndUpdate(
          { _id: sanitizedChallengeId }, 
          safeUpdateOps,
          { 
            new: true, 
            runValidators: true,
            session 
          }
        );

        if (!updatedChallenge) {
          throw ApiError.notFound(
            'Challenge not found after update',
            'CHALLENGE_UPDATE_FAILED'
          );
        }

        logger.info('[updateChallenge] Challenge updated successfully', {
          challengeId: sanitizedChallengeId,
          companyId: sanitizedCompanyId
        });

        return updatedChallenge;
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
      // Validate IDs using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When publishing challenge' }
      );
      
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(
        companyId, 
        'company', 
        { errorStatus: 400, additionalContext: 'When publishing challenge' }
      );

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        // Use $eq operator to prevent NoSQL injection
        const challenge = await Challenge.findOne({
          _id: { $eq: sanitizedChallengeId },
          company: { $eq: sanitizedCompanyId }
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
          challengeId: sanitizedChallengeId,
          companyId: sanitizedCompanyId
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
      // Build query filters using MongoSanitizer for safety
      const queryFilters: Record<string, any> = {};

      // Status filter with validation
      if (filters.status) {
        // Validate status is a valid enum value
        if (!Object.values(ChallengeStatus).includes(filters.status)) {
          throw ApiError.badRequest(
            `Invalid status value. Allowed values: ${Object.values(ChallengeStatus).join(', ')}`,
            'INVALID_STATUS'
          );
        }
        queryFilters.status = MongoSanitizer.buildEqualityCondition(filters.status);
      }

      // Company ID filter with validation
      if (filters.companyId) {
        const sanitizedCompanyId = MongoSanitizer.validateObjectId(
          filters.companyId, 
          'company', 
          { errorStatus: 400, additionalContext: 'In challenge filters' }
        );
        queryFilters.company = new Types.ObjectId(sanitizedCompanyId);
      }

      // Category filter with validation
      if (filters.category) {
        if (Array.isArray(filters.category)) {
          // Sanitize each category
          const sanitizedCategories = filters.category.map(cat => 
            MongoSanitizer.sanitizeString(cat, {
              fieldName: 'Category',
              maxLength: 100
            })
          );
          queryFilters.category = { $in: sanitizedCategories };
        } else {
          // Sanitize single category
          const sanitizedCategory = MongoSanitizer.sanitizeString(filters.category, {
            fieldName: 'Category',
            maxLength: 100
          });
          queryFilters.category = sanitizedCategory;
        }
      }

      // Difficulty filter with validation
      if (filters.difficulty) {
        // Validate difficulty is a valid enum value
        if (!Object.values(ChallengeDifficulty).includes(filters.difficulty)) {
          throw ApiError.badRequest(
            `Invalid difficulty value. Allowed values: ${Object.values(ChallengeDifficulty).join(', ')}`,
            'INVALID_DIFFICULTY'
          );
        }
        queryFilters.difficulty = MongoSanitizer.buildEqualityCondition(filters.difficulty);
      }

      // Visibility filter with validation
      if (filters.visibility) {
        // Validate visibility is a valid enum value
        if (!Object.values(ChallengeVisibility).includes(filters.visibility)) {
          throw ApiError.badRequest(
            `Invalid visibility value. Allowed values: ${Object.values(ChallengeVisibility).join(', ')}`,
            'INVALID_VISIBILITY'
          );
        }
        queryFilters.visibility = MongoSanitizer.buildEqualityCondition(filters.visibility);
      }

      // Date range filtering
      if (filters.startDate || filters.endDate) {
        queryFilters.createdAt = {};

        if (filters.startDate) {
          const startDate = new Date(filters.startDate);
          if (isNaN(startDate.getTime())) {
            throw ApiError.badRequest('Invalid start date format', 'INVALID_DATE_FORMAT');
          }
          queryFilters.createdAt.$gte = startDate;
        }

        if (filters.endDate) {
          const endDate = new Date(filters.endDate);
          if (isNaN(endDate.getTime())) {
            throw ApiError.badRequest('Invalid end date format', 'INVALID_DATE_FORMAT');
          }
          queryFilters.createdAt.$lte = endDate;
        }
      }

      // Text search functionality with sanitization
      if (filters.searchTerm) {
        // Validate and sanitize search term
        if (typeof filters.searchTerm !== 'string') {
          throw ApiError.badRequest('Search term must be a string', 'INVALID_SEARCH_TERM_TYPE');
        }

        // Use MongoSanitizer for safe regex building
        try {
          const titleRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);
          const descRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);
          const tagRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);

          queryFilters.$or = [
            { title: titleRegex },
            { description: descRegex },
            { tags: tagRegex }
          ];
        } catch (error) {
          // Log the error and throw a sanitized error message
          logger.error('[getChallenges] Error building search regex', {
            error: error instanceof Error ? error.message : String(error),
            searchTerm: filters.searchTerm.substring(0, 20) + 
              (filters.searchTerm.length > 20 ? '...' : '')
          });
          
          throw ApiError.badRequest(
            'Invalid search pattern. Please simplify your search term.',
            'INVALID_SEARCH_PATTERN'
          );
        }
      }

      // Validate and sanitize pagination parameters
      const page = typeof filters.page === 'number' ? 
        Math.max(1, filters.page) : 1;
        
      const maxLimit = 50; // Set maximum items per page
      const limit = typeof filters.limit === 'number' ? 
        Math.min(Math.max(1, filters.limit), maxLimit) : 10;

      // Validate and sanitize sort parameters
      const allowedSortFields = [
        'createdAt', 'title', 'deadline', 'difficulty', 
        'maxParticipants', 'currentParticipants', 'status'
      ];
      
      const sortBy = filters.sortBy || 'createdAt';
      const sortOrder = filters.sortOrder || 'desc';

      // Use MongoSanitizer to validate sort parameters
      const validatedSort = MongoSanitizer.validateSortParams(
        sortBy,
        sortOrder,
        allowedSortFields
      );
      
      const sortOptions: Record<string, 1 | -1> = {
        [validatedSort.sortBy]: validatedSort.sortOrder
      };

      // Use executePaginatedQuery for standardized pagination
      return await executePaginatedQuery<IChallenge>(
        Challenge,
        queryFilters,
        {
          page,
          limit,
          sortBy: validatedSort.sortBy,
          sortOrder: sortOrder,
          maxLimit
        },
        // Query modifier for populating relations and other operations
        (query) => query.populate('company', 'companyName logo').lean()
      );
    } catch (error) {
      logger.error('[getChallenges] Failed to retrieve challenges', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        filters: JSON.stringify({ 
          ...filters, 
          searchTerm: filters.searchTerm ? 
            (filters.searchTerm.substring(0, 20) + 
              (filters.searchTerm.length > 20 ? '...' : '')) : undefined 
        })
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
      // Validate IDs using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When closing challenge' }
      );
      
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(
        companyId, 
        'company', 
        { errorStatus: 400, additionalContext: 'When closing challenge' }
      );

      return await this.withTransaction(async (session) => {
        // Find challenge with company verification (security check)
        // Use $eq operator to prevent NoSQL injection
        const challenge = await Challenge.findOne({
          _id: { $eq: sanitizedChallengeId },
          company: { $eq: sanitizedCompanyId }
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
          challengeId: sanitizedChallengeId,
          companyId: sanitizedCompanyId
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
      // Validate challenge ID using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When deleting challenge' }
      );

      await this.withTransaction(async (session) => {
        // Find the challenge first to verify it exists
        // Use $eq operator to prevent NoSQL injection
        const challenge = await Challenge.findOne({ 
          _id: { $eq: sanitizedChallengeId } 
        }).session(session);
        
        if (!challenge) {
          throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
        }

        // Business validation - moved from validateChallengeCanBeDeleted
        if (challenge.status !== ChallengeStatus.DRAFT && challenge.currentParticipants > 0) {
          throw ApiError.forbidden(
            'Cannot delete an active or completed challenge with participants',
            'CHALLENGE_DELETION_FORBIDDEN'
          );
        }

        // Delete the challenge
        const deleteResult = await Challenge.findOneAndDelete({
          _id: { $eq: sanitizedChallengeId }
        }).session(session);

        if (!deleteResult) {
          throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
        }

        // Delete all solutions for this challenge
        // Use $eq operator to prevent NoSQL injection
        const solutionDeleteResult = await Solution.deleteMany({
          challenge: { $eq: sanitizedChallengeId }
        }).session(session);

        logger.info('[deleteChallenge] Challenge and solutions deleted successfully', {
          challengeId: sanitizedChallengeId,
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
        company: companyId
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
   * Mark a challenge as completed with final solution selections
   * @param challengeId - The ID of the challenge
   * @param companyId - The ID of the company completing the challenge
   * @returns The completed challenge and selected solutions
   */
  async markChallengeAsCompleted(
    challengeId: string, 
    companyId: string
  ): Promise<{ 
    challenge: IChallenge; 
    selectedSolutions: ISolution[];
  }> {
    logger.info('[markChallengeAsCompleted] Marking challenge as completed with final solutions', {
      challengeId,
      companyId
    });

    try {
      // Validate IDs using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge'
      );
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(
        companyId, 
        'company'
      );

      return await this.withTransaction(async (session) => {
        // Find the challenge and verify ownership
        const challenge = await Challenge.findOne({
          _id: { $eq: sanitizedChallengeId },
          company: { $eq: sanitizedCompanyId }
        }).session(session);

        if (!challenge) {
          throw ApiError.notFound(
            'Challenge not found or you do not have permission to complete it',
            'CHALLENGE_NOT_FOUND_OR_FORBIDDEN'
          );
        }

        // Verify challenge is in CLOSED status
        if (challenge.status !== ChallengeStatus.CLOSED) {
          throw ApiError.badRequest(
            'Only closed challenges can be marked as completed',
            'CHALLENGE_NOT_CLOSED'
          );
        }

        // Find all selected solutions for this challenge
        const selectedSolutions = await Solution.find({
          challenge: sanitizedChallengeId,
          status: SolutionStatus.SELECTED
        })
        .populate('student')
        .session(session);

        // If no solutions have been selected, we cannot complete the challenge
        if (selectedSolutions.length === 0) {
          throw ApiError.badRequest(
            'Cannot complete challenge without selecting at least one winning solution',
            'NO_SELECTED_SOLUTIONS'
          );
        }

        // Update challenge status
        challenge.status = ChallengeStatus.COMPLETED;
        challenge.completedAt = new Date();
        await challenge.save({ session });

        logger.info('[markChallengeAsCompleted] Challenge completed successfully', {
          challengeId: sanitizedChallengeId,
          companyId: sanitizedCompanyId,
          selectedSolutionsCount: selectedSolutions.length
        });

        return {
          challenge,
          selectedSolutions
        };
      });
    } catch (error) {
      logger.error('[markChallengeAsCompleted] Failed to complete challenge', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        companyId
      });

      if (error instanceof ApiError) throw error;
      throw ApiError.internal(
        'Failed to complete challenge with final selections',
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
      // Validate challenge ID using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: 'When fetching challenge with visibility' }
      );

      // Sanitize profileId if provided
      let sanitizedProfileId: string | undefined = undefined;
      if (profileId) {
        try {
          sanitizedProfileId = MongoSanitizer.validateObjectId(
            profileId, 
            'profile', 
            { required: false, errorStatus: 400, additionalContext: 'When fetching challenge with visibility' }
          );
        } catch (error) {
          logger.warn('[getChallengeByIdWithVisibility] Invalid profile ID, ignoring', {
            profileId,
            error: error instanceof Error ? error.message : String(error)
          });
          // Continue with undefined profileId
        }
      }

      // Use $eq operator to prevent NoSQL injection
      const challenge = await Challenge.findOne({ _id: { $eq: sanitizedChallengeId } })
        .populate('company', '-user -__v');

      if (!challenge) {
        throw ApiError.notFound('Challenge not found', 'CHALLENGE_NOT_FOUND');
      }

      // Check company ownership for company users
      const isCompanyOwner = userRole === UserRole.COMPANY &&
        sanitizedProfileId &&
        challenge.company &&
        typeof challenge.company !== 'string' &&
        challenge.company._id &&
        sanitizedProfileId === challenge.company._id.toString();

      // For private challenges, check institution access for students
      if (challenge.visibility === 'private' && userRole === UserRole.STUDENT) {
        // Sanitize university name if present
        const universityName = studentProfile?.university ? 
          MongoSanitizer.sanitizeString(studentProfile.university, {
            fieldName: 'University',
            maxLength: 200,
            required: false
          }) : undefined;

        if (!universityName ||
          !challenge.allowedInstitutions?.includes(universityName)) {
          logger.warn('[getChallengeByIdWithVisibility] Student access denied to private challenge', {
            challengeId: sanitizedChallengeId,
            studentUniversity: universityName,
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
            challengeId: sanitizedChallengeId
          });

          return restChallenge;
        }
      }

      logger.info('[getChallengeByIdWithVisibility] Challenge retrieved successfully', {
        challengeId: sanitizedChallengeId
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
   * Recursively sanitizes filter objects to prevent NoSQL injection
   * @param filters - Raw filter object that might contain malicious data
   * @returns Sanitized filter object safe to use in MongoDB queries
   */
  private sanitizeFilters(filters: Record<string, any>): Record<string, any> {
    const safeFilters: Record<string, any> = {};

    // Skip empty filters
    if (!filters || typeof filters !== 'object') {
      return safeFilters;
    }

    // Process each filter field
    for (const [key, value] of Object.entries(filters)) {
      // Skip undefined or null values
      if (value === undefined || value === null) continue;

      // Handle special cases like $or arrays
      if (key === '$or' && Array.isArray(value)) {
        safeFilters.$or = value.map(condition => this.sanitizeFilters(condition));
        continue;
      }

      if (key === '$and' && Array.isArray(value)) {
        safeFilters.$and = value.map(condition => this.sanitizeFilters(condition));
        continue;
      }

      // For normal fields, use $eq operator to ensure value is treated as literal
      if (typeof value === 'string') {
        safeFilters[key] = { $eq: String(value).trim() };
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        safeFilters[key] = { $eq: value };
      } else if (value instanceof Types.ObjectId) {
        safeFilters[key] = { $eq: value };
      } else if (value instanceof Date) {
        safeFilters[key] = { $eq: value };
      } else if (typeof value === 'object') {
        // For objects that might already contain MongoDB operators
        // Only allow specific safe operators and recursively sanitize their values
        const safeOps: Record<string, any> = {};
        const allowedOperators = ['$eq', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$regex', '$options'];
        
        // Check if it's a MongoDB query operator object
        const hasOperators = Object.keys(value).some(k => k.startsWith('$'));
        
        if (hasOperators) {
          // If it has operators, only allow whitelisted ones
          for (const [op, opValue] of Object.entries(value)) {
            if (allowedOperators.includes(op)) {
              // Special handling for regex to prevent ReDoS
              if (op === '$regex' && typeof opValue === 'string') {
                try {
                  // Use MongoSanitizer for safe regex
                  const safeRegex = MongoSanitizer.buildSafeRegexCondition(opValue);
                  safeOps.$regex = safeRegex.$regex;
                  safeOps.$options = safeRegex.$options;
                } catch (error) {
                  logger.warn(`Invalid regex pattern rejected: ${opValue}`);
                  // Skip this operator if regex is invalid
                }
              } else {
                safeOps[op] = opValue;
              }
            }
          }
          
          if (Object.keys(safeOps).length > 0) {
            safeFilters[key] = safeOps;
          }
        } else {
          // If not an operator object, treat as literal value
          safeFilters[key] = { $eq: value };
        }
      }
    }

    return safeFilters;
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

      // Sanitize userId if provided
      let sanitizedUserId: string | undefined = undefined;
      if (userId) {
        try {
          sanitizedUserId = MongoSanitizer.validateObjectId(
            userId, 
            'user', 
            { required: false, errorStatus: 400, additionalContext: 'When fetching challenges for user' }
          );
        } catch (error) {
          logger.warn('[getChallengesForUser] Invalid user ID, ignoring', {
            userId,
            error: error instanceof Error ? error.message : String(error)
          });
          // Continue with undefined userId
        }
      }

      // Build query filters with sanitization
      const queryFilters: Record<string, any> = {};

      // Sanitize difficulty
      if (filters.difficulty) {
        const difficulty = MongoSanitizer.sanitizeString(filters.difficulty, {
          fieldName: 'Difficulty', 
          maxLength: 50
        });
        
        // Validate against enum
        if (!Object.values(ChallengeDifficulty).includes(difficulty as ChallengeDifficulty)) {
          throw ApiError.badRequest(
            `Invalid difficulty value. Allowed values: ${Object.values(ChallengeDifficulty).join(', ')}`,
            'INVALID_DIFFICULTY'
          );
        }
        
        queryFilters.difficulty = { $eq: difficulty };
      }

      // Sanitize category
      if (filters.category) {
        if (Array.isArray(filters.category)) {
          // Sanitize each category
          const sanitizedCategories = filters.category.map(cat => 
            MongoSanitizer.sanitizeString(cat, {
              fieldName: 'Category',
              maxLength: 100
            })
          );
          queryFilters.category = { $in: sanitizedCategories };
        } else {
          // Sanitize single category
          const sanitizedCategory = MongoSanitizer.sanitizeString(filters.category, {
            fieldName: 'Category',
            maxLength: 100
          });
          queryFilters.category = { $eq: sanitizedCategory };
        }
      }

      // Search in title and description with enhanced security
      if (filters.searchTerm) {
        // Security: Validate search term to prevent DoS attacks
        if (typeof filters.searchTerm !== 'string') {
          logger.warn('[getChallengesForUser] Invalid search term type', {
            searchTermType: typeof filters.searchTerm
          });
          throw ApiError.badRequest('Search term must be a string', 'INVALID_SEARCH_TERM');
        }

        try {
          // Use MongoSanitizer for safe regex construction
          const titleRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);
          const descRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);
          const tagRegex = MongoSanitizer.buildSafeRegexCondition(filters.searchTerm);

          // Apply search filters using MongoDB's native string operators
          queryFilters.$or = [
            { title: titleRegex },
            { description: descRegex },
            { tags: tagRegex }
          ];

          logger.debug('[getChallengesForUser] Applied search filter', {
            searchPattern: filters.searchTerm.substring(0, 20) + 
              (filters.searchTerm.length > 20 ? '...' : '')
          });
        } catch (error) {
          logger.error('[getChallengesForUser] Error processing search term', {
            error: error instanceof Error ? error.message : String(error),
            searchTerm: filters.searchTerm.substring(0, 20) + 
              (filters.searchTerm.length > 20 ? '...' : '')
          });

          throw ApiError.badRequest(
            'Invalid search term format',
            'INVALID_SEARCH_FORMAT'
          );
        }
      }

      // Handle draft challenge visibility with proper sanitization
      if (filters.status === 'draft') {
        // Only company users can see their own draft challenges
        if (userRole === UserRole.COMPANY && sanitizedUserId) {
          // Get the company profile ID for the current user
          const companyProfile = await this.getCompanyProfileForUser(sanitizedUserId);
          if (companyProfile) {
            queryFilters.status = { $eq: ChallengeStatus.DRAFT };
            queryFilters.company = { $eq: companyProfile._id };
          } else {
            // If company profile not found, return empty result
            return createPaginationResult([], 0, filters.page || 1, filters.limit || 10);
          }
        } else if (userRole === UserRole.ADMIN) {
          // Admins can see all draft challenges
          queryFilters.status = { $eq: ChallengeStatus.DRAFT };
        } else {
          // Non-company/admin users can't see draft challenges
          return createPaginationResult([], 0, filters.page || 1, filters.limit || 10);
        }
      } else if (filters.status === 'all') {
        // For 'all' status requests:
        if (userRole === UserRole.COMPANY && sanitizedUserId) {
          // Companies can see all their own challenges plus active/closed/completed public challenges
          const companyProfile = await this.getCompanyProfileForUser(sanitizedUserId);
          if (companyProfile) {
            queryFilters.$or = [
              // Their own challenges of any status
              { company: { $eq: companyProfile._id } },
              // Active, closed, or completed public challenges
              {
                status: { $in: [ChallengeStatus.ACTIVE, ChallengeStatus.CLOSED, ChallengeStatus.COMPLETED] },
                visibility: { $eq: 'public' }
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
        // Validate if status is a valid enum value
        const status = MongoSanitizer.sanitizeString(filters.status, {
          fieldName: 'Status', 
          maxLength: 20
        });
        
        if (Object.values(ChallengeStatus).includes(status as ChallengeStatus)) {
          queryFilters.status = { $eq: status };
        } else {
          throw ApiError.badRequest(
            `Invalid status value. Allowed values: ${Object.values(ChallengeStatus).join(', ')}`,
            'INVALID_STATUS'
          );
        }
      } else {
        // Apply default filter if status not specified
        queryFilters.status = { $eq: ChallengeStatus.ACTIVE };
      }

      // Apply visibility filters based on user role with proper sanitization
      if (userRole === UserRole.STUDENT || !userRole) {
        // Initial visibility filter
        const visibilityFilter: Record<string, any> = { visibility: { $eq: 'public' } };

        // For authenticated students, also include private challenges they can access
        if (userRole === UserRole.STUDENT && sanitizedUserId && studentProfile?.university) {
          // Sanitize university name
          const university = MongoSanitizer.sanitizeString(studentProfile.university, {
            fieldName: 'University', 
            maxLength: 200,
            required: false
          });
          
          visibilityFilter.$or = [
            { visibility: { $eq: 'public' } },
            { visibility: { $eq: 'anonymous' } },
            {
              visibility: { $eq: 'private' },
              allowedInstitutions: { $in: [university] }
            }
          ];
        }

        queryFilters.$and = queryFilters.$and || [];
        queryFilters.$and.push(visibilityFilter);
      }

      // Sanitize pagination parameters
      const page = filters.page ? 
        Math.max(1, parseInt(String(filters.page))) : 1;
        
      const limit = filters.limit ? 
        Math.min(Math.max(1, parseInt(String(filters.limit))), 50) : 10;

      // Apply final sanitization to the entire query object
      const safeQueryFilters = this.sanitizeFilters(queryFilters);

      // Use pagination utilities for standardized handling
      const result = await executePaginatedQuery(
        Challenge,
        safeQueryFilters,
        {
          page,
          limit,
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
      // Validate challenge ID using MongoSanitizer
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(
        challengeId, 
        'challenge', 
        { errorStatus: 400, additionalContext: `During ${action} authorization` }
      );
      
      // Sanitize user/profile ID
      const sanitizedUserIdOrProfileId = MongoSanitizer.validateObjectId(
        userIdOrProfileId, 
        userRole === UserRole.COMPANY ? 'company profile' : 'user',
        { errorStatus: 400, additionalContext: `During ${action} authorization` }
      );

      // Get the challenge
      const challenge = await this.getChallengeById(sanitizedChallengeId);

      if (!challenge) {
        throw ApiError.notFound(
          `Challenge not found with id: ${sanitizedChallengeId}`,
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
        // Use strict comparison after sanitization
        if (challenge.company.toString() !== sanitizedUserIdOrProfileId) {
          throw ApiError.forbidden(
            `You do not have permission to ${action} this challenge`,
            'NOT_CHALLENGE_OWNER'
          );
        }
      }

      // Log successful authorization
      logger.info('[authorizeChallengeOwner] Challenge access authorized', {
        challengeId: sanitizedChallengeId,
        action,
        userIdOrProfileId: sanitizedUserIdOrProfileId,
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

// Export singleton instance for use in scheduler
export const challengeService = new ChallengeService();