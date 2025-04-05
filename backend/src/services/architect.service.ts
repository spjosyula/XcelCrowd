import mongoose, { Types, Document, ClientSession, FilterQuery } from 'mongoose';
import { ArchitectProfile, Solution, Challenge, User } from '../models';
import {
  IArchitectProfile,
  ISolution,
  SolutionStatus,
  ChallengeStatus,
  HTTP_STATUS,
  UserRole,
  IUser,
  IChallenge
} from '../models/interfaces';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { CreateUserDTO } from './user.service';
import { profileService } from './profile.service';
import { solutionService } from './solution.service';
import { BaseService } from './BaseService';

/**
 * Service for architect-related operations
 * Contains all business logic for architect operations
 */
export class ArchitectService extends BaseService {
  /**
   * Authorize an architect and return their profile ID
   * Business logic for architect authorization
   * 
   * @param userId - The ID of the user
   * @param action - Logging the arhcitect
   * @returns The architect profile ID
   * @throws ApiError if user is not an architect or profile doesn't exist
   */
  async authorizeArchitect(userId: string, action: string): Promise<string> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const profile = await this.getProfileByUserId(userId);

      if (!profile || !profile._id) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
      }

      logger.info(`Architect ${userId} authorized for ${action}`, {
        userId,
        action,
        profileId: profile._id.toString()
      });

      return profile._id.toString();
    } catch (error) {
      logger.error(`Authorization failed for architect ${userId} to ${action}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to authorize architect');
    }
  }

  /**
 * Create a new architect user with profile (admin only)
 * @param adminUserId - The ID of the admin creating the architect
 * @param architectData - User and profile data for the new architect
 * @returns Created user and profile information
 */
  async createArchitectUser(
    adminUserId: string,
    architectData: {
      email: string;
      password: string;
      firstName: string;
      lastName: string;
      specialization?: string;
      yearsOfExperience?: number;
      bio?: string;
      skills?: string[];
      certifications?: string[];
    }
  ): Promise<{ user: IUser; profile: IArchitectProfile }> {
    try {
      return await this.withTransaction(async (session) => {
        // Check if user with email already exists
        const existingUser = await User.findOne({ email: architectData.email }).session(session);
        if (existingUser) {
          throw new ApiError(HTTP_STATUS.CONFLICT, 'Email already in use');
        }
  
        // Create user document with architect role
        const userData: CreateUserDTO = {
          email: architectData.email,
          password: architectData.password,
          role: UserRole.ARCHITECT
        };
  
        // Create user in database
        const users = await User.create([userData], { session });
        const user = users[0];
  
        // Extract profile fields from architect data
        const { email, password, ...profileFields } = architectData;
  
        // Create architect profile
        const createdProfiles = await ArchitectProfile.create([
          {
            user: user._id,
            ...profileFields
          }
        ], { session });
        const architectProfile = createdProfiles[0];
  
        logger.info(`Architect user created by admin ${adminUserId}`, {
          adminId: adminUserId,
          architectId: user._id.toString(),
          architectEmail: user.email
        });
  
        return {
          user,
          profile: architectProfile
        };
      });
    } catch (error) {
      logger.error(`Error creating architect user: ${error instanceof Error ? error.message : String(error)}`, {
        adminId: adminUserId,
        email: architectData.email,
        error
      });
  
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to create architect user',
        true,
        'ARCHITECT_USER_CREATION_ERROR'
      );
    }
  }

  /**
   * Authorize an architect for a specific solution operation
   * Business logic for solution-specific authorization
   * 
   * @param userId - The ID of the user
   * @param solutionId - The ID of the solution
   * @param action - The action being performed (for logging)
   * @returns Object containing the architect ID and solution
   * @throws ApiError if authorization fails
   */
  async authorizeArchitectForSolution(
    userId: string,
    solutionId: string,
    action: string
  ): Promise<{ architectId: string, solution: ISolution }> {
    try {
      // Get architect profile ID
      const architectId = await this.authorizeArchitect(userId, action);

      // Validate solution ID format
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      // Get the solution 
      const solution = await this.getSolutionById(solutionId);

      // For review actions, verify the architect is the assigned reviewer
      if (action === 'review' && solution.reviewedBy) {
        const reviewerId = solution.reviewedBy.toString();

        if (reviewerId !== architectId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'Only the architect who claimed this solution can review it'
          );
        }
      }

      logger.info(`Architect ${userId} authorized for ${action} on solution ${solutionId}`, {
        userId,
        action,
        solutionId,
        architectId
      });

      return { architectId, solution };
    } catch (error) {
      logger.error(`Authorization failed for architect ${userId} to ${action} solution ${solutionId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to authorize architect for solution operation');
    }
  }

  /**
   * Get architect profile by user ID
   * @param userId - The ID of the user
   * @returns The architect profile
   */
  async getProfileByUserId(userId: string): Promise<IArchitectProfile> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const profile = await ArchitectProfile.findOne({ user: userId });
      if (!profile) {
        throw ApiError.notFound('Architect profile not found');
      }

      return profile;
    } catch (error) {
      logger.error(`Error fetching architect profile for user ${userId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve architect profile');
    }
  }

  /**
   * Create or update architect profile
   * @param userId - The ID of the user
   * @param profileData - The profile data to update
   * @returns The updated architect profile
   */
  async createOrUpdateProfile(userId: string, profileData: Partial<IArchitectProfile>): Promise<IArchitectProfile> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const profile = await ArchitectProfile.findOneAndUpdate(
        { user: userId },
        { ...profileData, user: userId },
        { new: true, upsert: true, runValidators: true }
      );

      logger.info(`Architect profile updated for user ${userId}`);
      return profile;
    } catch (error) {
      logger.error(`Error updating architect profile for user ${userId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update architect profile');
    }
  }

  /**
   * Parse and validate solution filter parameters
   * @param queryParams - Raw query parameters from request
   * @returns Validated and processed filter parameters
   */
  parseSolutionFilters(queryParams: any): {
    status: SolutionStatus;
    challengeId?: string;
    studentId?: string;
    page: number;
    limit: number;
  } {
    try {
      const status = queryParams.status as SolutionStatus || SolutionStatus.SUBMITTED;

      // Validate status enum value
      if (status && !Object.values(SolutionStatus).includes(status)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid status value');
      }

      // Parse and validate challengeId if provided
      let challengeId: string | undefined = undefined;
      if (queryParams.challengeId) {
        if (!Types.ObjectId.isValid(queryParams.challengeId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
        }
        challengeId = queryParams.challengeId;
      }

      // Parse and validate studentId if provided
      let studentId: string | undefined = undefined;
      if (queryParams.studentId) {
        if (!Types.ObjectId.isValid(queryParams.studentId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
        }
        studentId = queryParams.studentId;
      }

      // Parse and validate pagination parameters
      const page = queryParams.page ? parseInt(queryParams.page as string) : 1;
      if (isNaN(page) || page < 1) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Page must be a positive integer');
      }

      const limit = queryParams.limit ? parseInt(queryParams.limit as string) : 10;
      if (isNaN(limit) || limit < 1 || limit > 100) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Limit must be between 1 and 100');
      }

      return {
        status,
        challengeId,
        studentId,
        page,
        limit
      };
    } catch (error) {
      logger.error('Error parsing solution filters:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid filter parameters');
    }
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
    try {
      const { status = SolutionStatus.SUBMITTED, challengeId, studentId, page = 1, limit = 10 } = filters;

      // Build query with validation
      const query: Record<string, any> = { status };

      if (challengeId) {
        if (!Types.ObjectId.isValid(challengeId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
        }
        query.challenge = new Types.ObjectId(challengeId);
      }

      if (studentId) {
        if (!Types.ObjectId.isValid(studentId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
        }
        query.student = new Types.ObjectId(studentId);
      }

      const skip = (page - 1) * limit;

      // OPTIMIZATION: Use aggregation pipeline for efficient data loading with pagination
      const aggregationPipeline = [
        { $match: query },
        { $sort: { createdAt: -1 as 1 | -1 } },
        {
          $facet: {
            // Get total count
            totalCount: [
              { $count: 'count' }
            ],
            // Get paginated results with populated data
            paginatedResults: [
              { $skip: skip },
              { $limit: limit },
              // Populate challenge data
              {
                $lookup: {
                  from: 'challenges',
                  localField: 'challenge',
                  foreignField: '_id',
                  as: 'challenge'
                }
              },
              {
                $unwind: {
                  path: '$challenge',
                  preserveNullAndEmptyArrays: true
                }
              },
              // Populate student data
              {
                $lookup: {
                  from: 'studentprofiles',
                  localField: 'student',
                  foreignField: '_id',
                  as: 'student'
                }
              },
              {
                $unwind: {
                  path: '$student',
                  preserveNullAndEmptyArrays: true
                }
              },
              // Project only needed fields
              {
                $project: {
                  _id: 1,
                  status: 1,
                  submission: 1,
                  createdAt: 1,
                  'challenge._id': 1,
                  'challenge.title': 1,
                  'challenge.difficulty': 1,
                  'challenge.deadline': 1,
                  'student._id': 1,
                  'student.firstName': 1,
                  'student.lastName': 1,
                  'student.university': 1
                }
              }
            ]
          }
        }
      ];

      const results = await Solution.aggregate(aggregationPipeline);

      const total = results[0].totalCount[0]?.count || 0;
      const solutions = results[0].paginatedResults;

      return {
        solutions,
        total,
        page,
        limit
      };
    } catch (error) {
      logger.error('Error fetching pending solutions:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve pending solutions');
    }
  }

  /**
   * Get a specific solution by ID
   * @param solutionId - The ID of the solution
   * @returns The solution with populated references
   */
  async getSolutionById(solutionId: string): Promise<ISolution> {
    try {
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      const solution = await Solution.findById(solutionId)
        .populate('challenge')
        .populate('student')
        .populate('reviewedBy');

      if (!solution) {
        throw ApiError.notFound('Solution not found');
      }

      return solution;
    } catch (error) {
      logger.error(`Error fetching solution ${solutionId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve solution');
    }
  }

  /**
 * Claim an entire challenge for review
 * This assigns all solutions in this challenge to the architect
 * 
 * @param challengeId - The ID of the challenge to claim
 * @param architectId - The ID of the architect claiming the challenge
 * @returns The updated challenge with claimed status
 * @throws ApiError if challenge is not found, not in CLOSED status, or already claimed
 */
  async claimChallengeForReview(
    challengeId: string,
    architectId: string
  ): Promise<IChallenge> {
    // Validate input parameters
    if (!challengeId || !architectId) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Challenge ID and architect ID are required');
    }
  
    try {
      return await this.withTransaction(async (session) => {
        // Validate IDs with type checking
        if (!Types.ObjectId.isValid(challengeId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
        }
  
        if (!Types.ObjectId.isValid(architectId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
        }
  
        // Find the challenge using session
        const challenge = await Challenge.findById(challengeId)
          .session(session)
          .lean({ virtuals: true })
          .exec();
  
        // Comprehensive null checking
        if (!challenge) {
          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            `Challenge with ID ${challengeId} not found`
          );
        }
        
        // Check if review deadline has passed
        if (challenge.reviewDeadline && new Date() > challenge.reviewDeadline) {
          logger.warn(`Attempt to claim challenge with expired review deadline`, {
            challengeId,
            architectId,
            reviewDeadline: challenge.reviewDeadline
          });
      
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Cannot claim this challenge as the review deadline has passed: ${challenge.reviewDeadline.toISOString().split('T')[0]}`
          );
        }
  
        // Check if challenge is in CLOSED status
        if (challenge.status !== ChallengeStatus.CLOSED) {
          logger.warn(`Attempt to claim challenge in invalid status: ${challenge.status}`, {
            challengeId,
            architectId,
            currentStatus: challenge.status
          });
  
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Only challenges with status 'closed' can be claimed for review. Current status: ${challenge.status}`
          );
        }
  
        // Check if challenge is already claimed by another architect
        if (challenge.claimedBy && challenge.claimedBy.toString() !== architectId) {
          const claimingArchitect = await ArchitectProfile.findById(challenge.claimedBy)
            .session(session)
            .lean()
            .exec();
  
          logger.warn(`Conflict: Challenge already claimed by another architect`, {
            challengeId,
            attemptingArchitectId: architectId,
            currentClaimantId: challenge.claimedBy.toString(),
            claimantName: `${claimingArchitect?.firstName || 'Unknown'} ${claimingArchitect?.lastName || 'Architect'}`
          });
  
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            `This challenge has already been claimed by another architect: ${claimingArchitect?.firstName || 'Unknown'} ${claimingArchitect?.lastName || 'Architect'}`
          );
        }
  
        // If already claimed by this architect, just return the challenge
        if (challenge.claimedBy && challenge.claimedBy.toString() === architectId) {
          logger.info(`Challenge ${challengeId} already claimed by architect ${architectId}, returning existing claim`);
  
          // Return fresh data with population
          const populatedChallenge = await Challenge.findById(challengeId)
            .populate('claimedBy', 'firstName lastName specialization')
            .lean({ virtuals: true })
            .exec();
  
          if (!populatedChallenge) {
            throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found after claiming');
          }
  
          return populatedChallenge as IChallenge;
        }
  
        // Verify architect exists
        const architect = await ArchitectProfile.findById(architectId)
          .session(session)
          .lean()
          .exec();
  
        if (!architect) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
        }
  
        // Update challenge document to mark as claimed
        const updatedChallenge = await Challenge.findByIdAndUpdate(
          challengeId,
          {
            claimedBy: new Types.ObjectId(architectId),
            claimedAt: new Date(),
            updatedAt: new Date()
          },
          {
            new: true,
            runValidators: true,
            session
          }
        );
  
        if (!updatedChallenge) {
          throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update challenge');
        }
  
        // Get all SUBMITTED solutions for this challenge - use countDocuments first for optimization
        const submittedSolutionsCount = await Solution.countDocuments({
          challenge: challengeId,
          status: SolutionStatus.SUBMITTED
        }).session(session);
  
        // Only proceed with update if there are solutions to update
        if (submittedSolutionsCount > 0) {
          // Batch update all solutions with optimized query
          const updateResult = await Solution.updateMany(
            {
              challenge: challengeId,
              status: SolutionStatus.SUBMITTED
            },
            {
              $set: {
                status: SolutionStatus.UNDER_REVIEW,
                reviewedBy: new Types.ObjectId(architectId),
                updatedAt: new Date()
              }
            },
            { session }
          );
  
          logger.info(`Updated ${updateResult.modifiedCount} solutions to UNDER_REVIEW status for challenge ${challengeId}`);
  
          // Verify update succeeded
          if (updateResult.modifiedCount !== submittedSolutionsCount) {
            logger.warn(`Not all solutions were updated (${updateResult.modifiedCount}/${submittedSolutionsCount})`, {
              challengeId,
              architectId
            });
          }
        } else {
          logger.info(`No submitted solutions found for challenge ${challengeId}`);
        }
  
        // Log success with detailed information
        logger.info(`Challenge ${challengeId} successfully claimed by architect ${architectId}`, {
          challengeId,
          architectId,
          title: updatedChallenge.title,
          submittedSolutionsCount,
          timestamp: new Date().toISOString()
        });
  
        // Return the populated challenge with efficient projection
        const populatedChallenge = await Challenge.findById(challengeId)
          .populate({
            path: 'claimedBy',
            select: 'firstName lastName specialization',
          })
          .populate({
            path: 'company',
            select: 'companyName'
          })
          .lean({ virtuals: true })
          .exec();
  
        if (!populatedChallenge) {
          logger.error(`Challenge not found after successful claim operation`, {
            challengeId,
            architectId
          });
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found after claiming');
        }
  
        return populatedChallenge as IChallenge;
      });
    } catch (error) {
      // Comprehensive error logging with context
      logger.error(
        `Error claiming challenge: ${error instanceof Error ? error.message : String(error)}`,
        {
          challengeId,
          architectId,
          errorStack: error instanceof Error ? error.stack : undefined,
          errorName: error instanceof Error ? error.name : 'Unknown',
          timestamp: new Date().toISOString()
        }
      );
  
      // Error propagation with proper classification
      if (error instanceof ApiError) {
        throw error;
      }
  
      if (error instanceof mongoose.Error) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          `Database error: ${error.message}`,
          true,
          'DATABASE_ERROR'
        );
      }
  
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to claim challenge for review',
        true,
        'CLAIM_CHALLENGE_ERROR'
      );
    }
  }

  /**
 * Get all challenges claimed by an architect
 * @param architectId - Architect profile ID
 * @param options - Pagination and filtering options
 * @returns List of claimed challenges with their solutions stats
 */
  async getClaimedChallenges(
    architectId: string,
    options: {
      status?: ChallengeStatus;
      page?: number;
      limit?: number;
    } = {}
  ): Promise<{
    challenges: Array<IChallenge & { solutionStats?: Record<string, number> }>;
    total: number;
    page: number;
    limit: number;
  }> {
    try {
      // Validate architect ID
      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      // Parse options with default values
      const {
        status,
        page = 1,
        limit = 10
      } = options;

      // Build query with proper type safety
      const query: FilterQuery<IChallenge> = {
        claimedBy: new Types.ObjectId(architectId)
      };

      // Add status filter if specified and valid
      if (status && Object.values(ChallengeStatus).includes(status)) {
        query.status = status;
      }

      // Calculate pagination parameters
      const skip = (Number(page) - 1) * Number(limit);

      // Execute query with pagination using Promise.all for efficiency
      const [challenges, total] = await Promise.all([
        Challenge.find(query)
          .populate({
            path: 'company',
            select: 'companyName logo industry location'
          })
          .populate({
            path: 'claimedBy',
            select: 'firstName lastName specialization'
          })
          .sort({ claimedAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .lean({ virtuals: true }),
        Challenge.countDocuments(query)
      ]);

      // Get solution stats for each challenge using aggregation pipeline
      const challengeIds = challenges.map(c => c._id);

      // Only run aggregation if we have challenges
      let solutionStats: Record<string, Record<string, number>> = {};
      if (challengeIds.length > 0) {
        const solutionAggregation = await Solution.aggregate([
          {
            $match: {
              challenge: { $in: challengeIds },
            }
          },
          {
            $group: {
              _id: {
                challenge: "$challenge",
                status: "$status"
              },
              count: { $sum: 1 }
            }
          }
        ]);

        // Transform aggregation results to a more usable format
        // challengeId -> { status: count, status2: count }
        solutionStats = solutionAggregation.reduce((acc, curr) => {
          const challengeId = curr._id.challenge.toString();
          const status = curr._id.status;

          if (!acc[challengeId]) {
            acc[challengeId] = {};
          }

          acc[challengeId][status] = curr.count;
          return acc;
        }, {} as Record<string, Record<string, number>>);
      }

      // Enhance challenges with solution statistics
      const enhancedChallenges = challenges.map(challenge => {
        const challengeId = challenge._id.toString();
        return {
          ...challenge,
          solutionStats: solutionStats[challengeId] || {},
          // Add total solutions count
          totalSolutions: Object.values(solutionStats[challengeId] || {})
            .reduce((sum, count) => sum + count, 0)
        };
      });

      logger.debug(`Retrieved ${enhancedChallenges.length} claimed challenges for architect ${architectId}`, {
        architectId,
        totalChallenges: total,
        currentPage: page
      });

      return {
        challenges: enhancedChallenges,
        total,
        page: Number(page),
        limit: Number(limit)
      };
    } catch (error) {
      logger.error(
        `Error getting claimed challenges: ${error instanceof Error ? error.message : String(error)}`,
        {
          architectId,
          options: JSON.stringify(options),
          error: error instanceof Error ? {
            name: error.name,
            message: error.message,
            stack: error.stack
          } : String(error)
        }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve claimed challenges',
        true,
        'CLAIMED_CHALLENGES_RETRIEVAL_ERROR'
      );
    }
  }
  /**
   * Validate if an architect can review a solution
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect reviewing
   * @throws ApiError if validation fails
   */
  async validateSolutionForReview(solutionId: string, architectId: string): Promise<ISolution> {
    try {
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      const solution = await Solution.findById(solutionId);

      if (!solution) {
        throw ApiError.notFound('Solution not found');
      }

      if (solution.status !== SolutionStatus.SUBMITTED && solution.status !== SolutionStatus.UNDER_REVIEW) {
        throw ApiError.badRequest('Solution has already been reviewed');
      }

      // If solution is under review, verify it's assigned to this architect
      if (solution.status === SolutionStatus.UNDER_REVIEW &&
        solution.reviewedBy &&
        solution.reviewedBy.toString() !== architectId) {
        throw ApiError.forbidden('This solution is being reviewed by another architect');
      }

      return solution;
    } catch (error) {
      logger.error(`Error validating solution ${solutionId} for review:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to validate solution for review');
    }
  }
  async claimChallengeById(userId: string, challengeId: string): Promise<IChallenge> {
    // Validate challenge ID
    if (!Types.ObjectId.isValid(challengeId)) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
    }

    // Get architect profile ID
    const architectId = await profileService.getArchitectProfileId(userId);

    // Claim the challenge
    const challenge = await this.claimChallengeForReview(challengeId, architectId);

    return challenge;
  }

  async getArchitectClaimedChallenges(
    userId: string,
    queryParams: any
  ): Promise<{
    challenges: Array<IChallenge & { solutionStats?: Record<string, number> }>;
    total: number;
    page: number;
    limit: number;
  }> {
    // Get architect profile ID
    const architectId = await profileService.getArchitectProfileId(userId);

    // Parse query parameters
    const status = queryParams.status as ChallengeStatus | undefined;
    const page = queryParams.page ? parseInt(queryParams.page as string) : 1;
    const limit = queryParams.limit ? parseInt(queryParams.limit as string) : 10;

    // Get claimed challenges
    return this.getClaimedChallenges(architectId, { status, page, limit });
  }

  async claimSolutionViaChallenge(
    userId: string,
    solutionId: string
  ): Promise<ISolution> {
    // Validate IDs
    if (!Types.ObjectId.isValid(solutionId)) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
    }

    // Get architect profile ID
    const architectId = await profileService.getArchitectProfileId(userId);

    // Get the solution to find its challenge
    const solution = await Solution.findById(solutionId).select('challenge');

    if (!solution) {
      throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
    }

    // Extract the challenge ID
    const challengeId = solution.challenge?.toString();

    if (!challengeId) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Solution has no associated challenge');
    }

    // Claim the entire challenge
    await this.claimChallengeForReview(challengeId, architectId);

    // Get the updated solution
    const updatedSolution = await solutionService.getSolutionById(solutionId, userId, UserRole.ARCHITECT);

    return updatedSolution;
  }



  /**
   * Process review data and validate it
   * @param reviewData - The submitted review data
   * @returns Validated review data
   */
  validateReviewData(reviewData: any): { status: SolutionStatus; feedback: string; score?: number } {
    try {
      // Validate status
      if (!reviewData.status || !Object.values(SolutionStatus).includes(reviewData.status)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid status value');
      }

      // Only allow specific statuses for reviews
      if (reviewData.status !== SolutionStatus.APPROVED && reviewData.status !== SolutionStatus.REJECTED) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Review status must be either APPROVED or REJECTED');
      }

      // Validate feedback
      if (!reviewData.feedback || typeof reviewData.feedback !== 'string' || reviewData.feedback.length < 10) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Feedback must be at least 10 characters');
      }

      // Validate score if provided
      if (reviewData.score !== undefined) {
        const score = Number(reviewData.score);
        if (isNaN(score) || score < 0 || score > 100) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Score must be a number between 0 and 100');
        }

        return {
          status: reviewData.status,
          feedback: reviewData.feedback,
          score
        };
      }

      return {
        status: reviewData.status,
        feedback: reviewData.feedback
      };
    } catch (error) {
      logger.error('Error validating review data:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid review data');
    }
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
    try {
      return await this.withTransaction(async (session) => {
        // Validate solution for review
        const solution = await this.validateSolutionForReview(solutionId, architectId);
  
        // If approving, check if challenge approval limit reached
        if (reviewData.status === SolutionStatus.APPROVED) {
          const challenge = await Challenge.findById(solution.challenge).session(session);
          if (!challenge) {
            throw ApiError.notFound('Challenge not found');
          }
  
          if (challenge.isApprovalLimitReached()) {
            throw ApiError.badRequest('Maximum number of approved solutions reached for this challenge');
          }
  
          // Increment the approved solutions count
          challenge.approvedSolutionsCount += 1;
          await challenge.save({ session });
        }
  
        // Update solution with review data
        solution.status = reviewData.status;
        solution.feedback = reviewData.feedback;
        solution.reviewedBy = new Types.ObjectId(architectId);
        solution.reviewedAt = new Date();
  
        if (reviewData.score !== undefined) {
          solution.score = reviewData.score;
        }
  
        await solution.save({ session });
  
        logger.info(`Solution ${solutionId} reviewed by architect ${architectId} with status ${reviewData.status}`);
  
        // Return populated solution
        const updatedSolution = await Solution.findById(solutionId)
          .populate([
            { path: 'challenge' },
            { path: 'student' },
            { path: 'reviewedBy' }
          ])
          .session(session);
  
        if (!updatedSolution) {
          throw ApiError.notFound('Solution not found after review');
        }
  
        return updatedSolution;
      });
    } catch (error) {
      logger.error(`Error reviewing solution ${solutionId}:`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        solutionId,
        architectId
      });
      
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to review solution',
        true,
        'SOLUTION_REVIEW_ERROR'
      );
    }
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
    try {
      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      const architectObjectId = new Types.ObjectId(architectId);

      // OPTIMIZATION: Use aggregation with $facet to get all stats in one query
      const aggregationResults = await Solution.aggregate([
        {
          $facet: {
            // Count documents by status for this architect
            statusCounts: [
              {
                $match: { reviewedBy: architectObjectId }
              },
              {
                $group: {
                  _id: '$status',
                  count: { $sum: 1 }
                }
              }
            ],
            // Count total pending solutions
            pendingCount: [
              {
                $match: { status: SolutionStatus.SUBMITTED }
              },
              {
                $count: 'count'
              }
            ],
            // Recent activity
            recentActivity: [
              {
                $match: { reviewedBy: architectObjectId }
              },
              {
                $sort: { reviewedAt: -1 }
              },
              {
                $limit: 5
              },
              {
                $lookup: {
                  from: 'challenges',
                  localField: 'challenge',
                  foreignField: '_id',
                  as: 'challenge'
                }
              },
              {
                $unwind: {
                  path: '$challenge',
                  preserveNullAndEmptyArrays: true
                }
              },
              {
                $lookup: {
                  from: 'users',
                  localField: 'student',
                  foreignField: '_id',
                  as: 'student'
                }
              },
              {
                $unwind: {
                  path: '$student',
                  preserveNullAndEmptyArrays: true
                }
              },
              {
                $project: {
                  _id: 1,
                  status: 1,
                  reviewedAt: 1,
                  'challenge._id': 1,
                  'challenge.title': 1,
                  'student._id': 1,
                  'student.firstName': 1,
                  'student.lastName': 1
                }
              }
            ]
          }
        }
      ]);

      const results = aggregationResults[0];

      // Process status counts into the expected format
      const statusCountsMap = results.statusCounts.reduce((acc: any, curr: any) => {
        acc[curr._id] = curr.count;
        return acc;
      }, {});

      return {
        totalReviewed: statusCountsMap[SolutionStatus.APPROVED] + statusCountsMap[SolutionStatus.REJECTED] || 0,
        approved: statusCountsMap[SolutionStatus.APPROVED] || 0,
        rejected: statusCountsMap[SolutionStatus.REJECTED] || 0,
        pendingReview: results.pendingCount[0]?.count || 0,
        recentActivity: results.recentActivity
      };
    } catch (error) {
      logger.error(`Error fetching dashboard statistics for architect ${architectId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve dashboard statistics');
    }
  }

  /**
   * Claim a solution for review -> Architect should claim a challenge instead, this method exists for backward compatibility
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect
   * @returns The updated solution
   */
  async claimSolutionForReview(solutionId: string, architectId: string): Promise<ISolution> {
    try {
      return await this.withTransaction(async (session) => {
        if (!Types.ObjectId.isValid(solutionId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
        }
  
        if (!Types.ObjectId.isValid(architectId)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
        }
  
        const solution = await Solution.findById(solutionId).session(session);
  
        if (!solution) {
          throw ApiError.notFound('Solution not found');
        }
  
        if (solution.status !== SolutionStatus.SUBMITTED) {
          throw ApiError.badRequest('Solution is not available for review');
        }
  
        // Update solution status and assign reviewer
        solution.status = SolutionStatus.UNDER_REVIEW;
        solution.reviewedBy = new Types.ObjectId(architectId);
        await solution.save({ session });
  
        return solution.populate([
          { path: 'challenge' },
          { path: 'student' }
        ]);
      });
    } catch (error) {
      logger.error(`Error claiming solution ${solutionId} for review:`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        solutionId,
        architectId
      });
      
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to claim solution for review',
        true,
        'CLAIM_SOLUTION_ERROR'
      );
    }
  }

  /**
   * Validate solution selection request data
   * @param challengeId - The ID of the challenge
   * @param solutionIds - Array of solution IDs to validate
   * @returns Validated solution IDs array
   */
  validateSolutionSelectionData(challengeId: string, solutionIds: any): string[] {
    try {
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      // Validate solution IDs array
      if (!Array.isArray(solutionIds) || solutionIds.length === 0) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'At least one solution ID must be provided');
      }

      // Validate each solution ID
      const validatedIds = solutionIds.map(id => {
        if (!Types.ObjectId.isValid(id)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, `Invalid solution ID format: ${id}`);
        }
        return id;
      });

      return validatedIds;
    } catch (error) {
      logger.error('Error validating solution selection data:', error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution selection data');
    }
  }

  /**
 * Validate solutions for company selection
 * @param challengeId - The ID of the challenge
 * @param solutionIds - Array of solution IDs to validate
 * @param architectId - The ID of the architect
 * @returns The solutions and challenge
 */
  async validateSolutionsForSelection(
    challengeId: string,
    solutionIds: string[],
    architectId: string,
    session?: ClientSession
  ): Promise<{ solutions: ISolution[]; challenge: any }> {
    try {
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      const validatedSolutionIds = solutionIds.map(id => {
        if (!Types.ObjectId.isValid(id)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, `Invalid solution ID format: ${id}`);
        }
        return new Types.ObjectId(id);
      });

      // Fetch challenge and authorization status in parallel
      const [challenge, hasReviewed, solutions] = await Promise.all([
        Challenge.findById(challengeId).session(session || null),
        Solution.exists({
          challenge: challengeId,
          reviewedBy: new Types.ObjectId(architectId)
        }).session(session || null),
        Solution.find({
          _id: { $in: validatedSolutionIds },
          challenge: challengeId,
          status: SolutionStatus.APPROVED
        }).session(session || null)
      ]);

      if (!challenge) {
        throw ApiError.notFound('Challenge not found');
      }

      // Check if the architect is authorized to select solutions
      if (!hasReviewed) {
        throw ApiError.forbidden('You are not authorized to select solutions for this challenge');
      }

      // Check if the number of solutions doesn't exceed the maximum allowed
      if (challenge.maxApprovedSolutions && solutionIds.length > challenge.maxApprovedSolutions) {
        throw ApiError.badRequest(`Cannot select more than ${challenge.maxApprovedSolutions} solutions for this challenge`);
      }

      // Validate all required solutions are found with correct status
      if (solutions.length !== solutionIds.length) {
        throw ApiError.badRequest('One or more solution IDs are invalid, not approved, or not part of this challenge');
      }

      return { solutions, challenge };
    } catch (error) {
      logger.error(`Error validating solutions for selection:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to validate solutions for selection');
    }
  }

  /**
 * Get pending challenges available for review
 * @param userId - The ID of the architect user
 * @param queryParams - Query parameters for filtering and pagination
 * @returns Paginated list of pending challenges
 */
  async getPendingChallenges(
    userId: string,
    queryParams: any
  ): Promise<{
    challenges: Array<IChallenge & { solutionsCount?: number }>;
    total: number;
    page: number;
    limit: number;
  }> {
    try {
      // Parse query parameters
      const status = queryParams.status as ChallengeStatus || ChallengeStatus.CLOSED;
      const page = queryParams.page ? parseInt(queryParams.page as string) : 1;
      const limit = queryParams.limit ? parseInt(queryParams.limit as string) : 10;
      const skip = (page - 1) * limit;

      // Get architect profile ID for filtering out already claimed challenges
      const architectId = await profileService.getArchitectProfileId(userId);

      // Build query - looking for challenges in CLOSED status without a claimedBy field
      // or not claimed by this architect
      const query: FilterQuery<IChallenge> = {
        status: status,
        $or: [
          { claimedBy: { $exists: false } },
          { claimedBy: null }
        ]
      };

      // Use aggregation for efficient query with counts
      const aggregationPipeline = [
        { $match: query },
        { $sort: { deadline: -1 as 1 | -1 } },
        {
          $facet: {
            // Get total count
            totalCount: [
              { $count: 'count' }
            ],
            // Get paginated results with populated data
            paginatedResults: [
              { $skip: skip },
              { $limit: limit },
              // Add solutions count
              {
                $lookup: {
                  from: 'solutions',
                  let: { challengeId: '$_id' },
                  pipeline: [
                    {
                      $match: {
                        $expr: { $eq: ['$challenge', '$$challengeId'] },
                        status: SolutionStatus.SUBMITTED
                      }
                    },
                    { $count: 'count' }
                  ],
                  as: 'solutionsData'
                }
              },
              // Populate company data
              {
                $lookup: {
                  from: 'companies',
                  localField: 'company',
                  foreignField: '_id',
                  as: 'company'
                }
              },
              {
                $unwind: {
                  path: '$company',
                  preserveNullAndEmptyArrays: true
                }
              },
              // Format the solutions count
              {
                $addFields: {
                  solutionsCount: {
                    $cond: {
                      if: { $gt: [{ $size: '$solutionsData' }, 0] },
                      then: { $arrayElemAt: ['$solutionsData.count', 0] },
                      else: 0
                    }
                  }
                }
              },
              // Project needed fields only
              {
                $project: {
                  _id: 1,
                  title: 1,
                  description: 1,
                  status: 1,
                  difficulty: 1,
                  deadline: 1,
                  createdAt: 1,
                  solutionsCount: 1,
                  'company._id': 1,
                  'company.companyName': 1,
                  'company.logo': 1,
                }
              }
            ]
          }
        }
      ];

      const results = await Challenge.aggregate(aggregationPipeline);

      const total = results[0].totalCount[0]?.count || 0;
      const challenges = results[0].paginatedResults;

      logger.info(`Retrieved ${challenges.length} pending challenges for architect ${userId}`, {
        architectId,
        totalChallenges: total,
        currentPage: page
      });

      return {
        challenges,
        total,
        page,
        limit
      };
    } catch (error) {
      logger.error(
        `Error getting pending challenges: ${error instanceof Error ? error.message : String(error)}`,
        {
          userId,
          queryParams: JSON.stringify(queryParams),
          error: error instanceof Error ? {
            name: error.name,
            message: error.message,
            stack: error.stack
          } : String(error)
        }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve pending challenges',
        true,
        'PENDING_CHALLENGES_RETRIEVAL_ERROR'
      );
    }
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
    try {
      return await this.withTransaction(async (session) => {
        // Use the validation method to verify all selections are valid
        const { solutions, challenge } = await this.validateSolutionsForSelection(
          challengeId,
          solutionIds,
          architectId,
          session
        );
      
        const validatedSolutionIds = solutions.map(solution => solution._id);
      
        // Add result verification
        const bulkWriteResult = await Solution.bulkWrite(
          validatedSolutionIds.map((id) => ({
            updateOne: {
              filter: { _id: id },
              update: {
                $set: {
                  status: SolutionStatus.SELECTED,
                  selectedAt: new Date(),
                  selectedBy: new Types.ObjectId(architectId)
                }
              }
            }
          })),
          { session }
        );
      
        // Verify that all documents were updated as expected
        if (bulkWriteResult.modifiedCount !== validatedSolutionIds.length) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR, 
            'Not all solutions could be updated to SELECTED status'
          );
        }
      
        // Update challenge status
        challenge.status = ChallengeStatus.COMPLETED;
        await challenge.save({ session });
      
        logger.info(`${validatedSolutionIds.length} solutions selected for challenge ${challengeId} by architect ${architectId}`, {
          challengeId,
          architectId,
          solutionCount: validatedSolutionIds.length
        });
      
        // Return the updated solutions with optimized population
        return await Solution.find({ _id: { $in: validatedSolutionIds } })
          .populate([
            { path: 'challenge', select: 'title description status' },
            { path: 'student', select: 'firstName lastName email' },
            { path: 'reviewedBy', select: 'firstName lastName' }
          ])
          .session(session);
      });
    } catch (error) {
      // Improved error handling with more context
      logger.error(`Error selecting solutions for company:`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        challengeId,
        architectId,
        solutionCount: solutionIds.length
      });
      
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Failed to select solutions for company',
        true,
        'SOLUTION_SELECTION_ERROR'
      );
    }
  }
}

export const architectService = new ArchitectService();