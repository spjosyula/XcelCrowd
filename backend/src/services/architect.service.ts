import { Types, Document, ClientSession } from 'mongoose';
import { ArchitectProfile, Solution, Challenge } from '../models';
import {
  IArchitectProfile,
  ISolution,
  SolutionStatus,
  ChallengeStatus,
  HTTP_STATUS,
  UserRole
} from '../models/interfaces';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';

/**
 * Service for architect-related operations
 * Contains all business logic for architect operations
 */
export class ArchitectService {
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
      // Start a transaction for atomicity
      const session = await Solution.startSession();
      session.startTransaction();

      try {
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

        // Commit the transaction
        await session.commitTransaction();

        logger.info(`Solution ${solutionId} reviewed by architect ${architectId} with status ${reviewData.status}`);

        // Return populated solution
        const updatedSolution = await Solution.findById(solutionId).populate([
          { path: 'challenge' },
          { path: 'student' },
          { path: 'reviewedBy' }
        ]);

        if (!updatedSolution) {
          throw ApiError.notFound('Solution not found after review');
        }

        return updatedSolution;
      } catch (error) {
        // Abort transaction on error
        await session.abortTransaction();
        throw error;
      } finally {
        // End session
        session.endSession();
      }
    } catch (error) {
      logger.error(`Error reviewing solution ${solutionId}:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to review solution');
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
   * Claim a solution for review
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect
   * @returns The updated solution
   */
  async claimSolutionForReview(solutionId: string, architectId: string): Promise<ISolution> {
    const session = await Solution.startSession();
    try {
      session.startTransaction();
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

      if (solution.status !== SolutionStatus.SUBMITTED) {
        throw ApiError.badRequest('Solution is not available for review');
      }

      // Update solution status and assign reviewer
      solution.status = SolutionStatus.UNDER_REVIEW;
      solution.reviewedBy = new Types.ObjectId(architectId);
      await solution.save({ session });

      await session.commitTransaction();

      return solution.populate([
        { path: 'challenge' },
        { path: 'student' }
      ]);
    } catch (error) {
      logger.error(`Error claiming solution ${solutionId} for review:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to claim solution for review');
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
    // Start a transaction for atomicity
    const session = await Solution.startSession();

    try {
      session.startTransaction();

      // Use the validation method to verify all selections are valid
      // This avoids duplicating validation logic
      const { solutions, challenge } = await this.validateSolutionsForSelection(
        challengeId,
        solutionIds,
        architectId,
        session
      );

      // Prepare solution IDs for bulk update
      const validatedSolutionIds = solutions.map(solution => solution._id);

      // Update solutions to SELECTED status using bulkWrite for efficiency
      await Solution.bulkWrite(
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

      // Update challenge status
      challenge.status = ChallengeStatus.COMPLETED;
      await challenge.save({ session });

      // Commit the transaction
      await session.commitTransaction();

      logger.info(`${solutionIds.length} solutions selected for challenge ${challengeId} by architect ${architectId}`);

      // Return the updated solutions with optimized population (select only needed fields)
      return await Solution.find({ _id: { $in: validatedSolutionIds } })
        .populate([
          { path: 'challenge', select: 'title description status' },
          { path: 'student', select: 'firstName lastName email' },
          { path: 'reviewedBy', select: 'firstName lastName' }
        ]);

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();
      logger.error(`Error selecting solutions for company:`, error);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to select solutions for company');
    } finally {
      // End session in finally block to ensure it always gets closed
      session.endSession();
    }
  }
}