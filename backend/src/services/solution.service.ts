import mongoose, { Types } from 'mongoose';
import Solution from '../models/Solution';
import Challenge from '../models/Challenge';
import StudentProfile from '../models/StudentProfile';
import { profileService } from './profile.service';
import { PipelineStage } from 'mongoose';
import {
  SolutionStatus,
  ChallengeStatus,
  ChallengeVisibility,
  UserRole,
  ISolution,
  IChallenge,
  ChallengeDifficulty,
  EvaluationDecision
} from '../models/interfaces';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { PaginationOptions, PaginationResult } from '../utils/paginationUtils';
import { MongoSanitizer } from '../utils/mongo.sanitize';
import { BaseService } from './BaseService';
import { HTTP_STATUS } from '../constants';


/**
 * Solution data type for submission
 */
interface SolutionSubmissionData {
  title: string;
  description: string;
  submissionUrl: string;
  tags?: string[];
}

/**
 * Service for solution-related operations
 * Contains all business logic for solution management
 */
export class SolutionService extends BaseService {

  private getDocumentId(doc: any): string {
    if (!doc) return 'unknown-id';
    if (doc._id) {
      return doc._id instanceof Types.ObjectId
        ? doc._id.toString()
        : typeof doc._id === 'string'
          ? doc._id
          : String(doc._id);
    }
    return typeof doc === 'string' ? doc : 'unknown-id';
  }

  /**
   * Submit a solution to a challenge
   * @param studentId - The ID of the student submitting the solution
   * @param challengeId - The ID of the challenge
   * @param solutionData - The solution data
   * @returns The submitted solution
   * @throws ApiError if validation fails or unauthorized
   */
  async submitSolution(
    studentId: string,
    challengeId: string,
    solutionData: SolutionSubmissionData,
    idempotencyKey?: string // Optional idempotency key for deduplication
  ): Promise<ISolution> {
    try {
      // Sanitize and validate IDs using MongoSanitizer to prevent NoSQL injection
      const sanitizedStudentId = MongoSanitizer.validateObjectId(studentId, 'student');
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(challengeId, 'challenge');

      // Validate solution data
      if (!solutionData.title || typeof solutionData.title !== 'string') {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Title is required and must be a string');
      }
      if (!solutionData.description || typeof solutionData.description !== 'string') {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Description is required and must be a string');
      }
      if (!solutionData.submissionUrl || typeof solutionData.submissionUrl !== 'string') {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Submission URL is required and must be a string');
      }

      // Sanitize all string inputs
      const sanitizedTitle = String(solutionData.title).trim();
      const sanitizedDescription = String(solutionData.description).trim();
      const sanitizedSubmissionUrl = String(solutionData.submissionUrl).trim();

      // Validate and sanitize tags if provided
      const sanitizedTags = solutionData.tags?.map(tag => String(tag).trim()) || [];

      // Log submission attempt
      logger.info(`Student ${sanitizedStudentId} attempting to submit solution for challenge ${sanitizedChallengeId}`);

      // If idempotencyKey provided, check for existing submission with this key
      if (idempotencyKey) {
        const sanitizedKey = String(idempotencyKey).trim();
        const existingSolutionWithKey = await Solution.findOne({
          idempotencyKey: { $eq: sanitizedKey },
          student: { $eq: new Types.ObjectId(sanitizedStudentId) }
        }).populate('challenge').populate('student');

        if (existingSolutionWithKey) {
          logger.info(`Found existing solution with idempotency key ${sanitizedKey}`, {
            studentId: sanitizedStudentId,
            solutionId: existingSolutionWithKey._id
          });
          return existingSolutionWithKey;
        }
      }

      return await this.withTransaction(async (session) => {
        // Increment the current participants count atomically with transaction support
        const updatedChallenge = await Challenge.findByIdAndUpdate(
          sanitizedChallengeId,
          { $inc: { currentParticipants: 1 } },
          { session, new: true }
        );

        if (!updatedChallenge) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
        }

        // Check if challenge deadline has passed
        if (updatedChallenge.isDeadlinePassed()) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Challenge deadline has passed, no new solutions can be submitted'
          );
        }

        // Check if student is eligible to participate (e.g., university restrictions)
        if (updatedChallenge.visibility === ChallengeVisibility.PRIVATE && updatedChallenge.allowedInstitutions?.length) {
          const student = await StudentProfile.findById(sanitizedStudentId).session(session);
          if (!student) {
            throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
          }

          const isEligible = student.university &&
            updatedChallenge.allowedInstitutions.includes(student.university);

          if (!isEligible) {
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You are not eligible to participate in this challenge due to university restrictions'
            );
          }
        }

        // Check for duplicate submission using $eq operator to prevent injection
        const existingSolution = await Solution.findOne({
          student: { $eq: new Types.ObjectId(sanitizedStudentId) },
          challenge: { $eq: new Types.ObjectId(sanitizedChallengeId) }
        }).session(session);

        if (existingSolution) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            'You have already submitted a solution for this challenge',
            true,
            'DUPLICATE_SUBMISSION'
          );
        }

        // Create the solution with sanitized data
        const solution = new Solution({
          student: new Types.ObjectId(sanitizedStudentId),
          challenge: new Types.ObjectId(sanitizedChallengeId),
          title: sanitizedTitle,
          description: sanitizedDescription,
          submissionUrl: sanitizedSubmissionUrl,
          status: SolutionStatus.SUBMITTED,
          tags: sanitizedTags,
          ...(idempotencyKey && { idempotencyKey: String(idempotencyKey).trim() })
        });

        await solution.save({ session });

        logger.info(
          `Student ${sanitizedStudentId} successfully submitted solution ${solution._id} for challenge ${sanitizedChallengeId}`,
          {
            studentId: sanitizedStudentId,
            challengeId: sanitizedChallengeId,
            solutionId: solution._id
          }
        );

        // Get the populated solution (still within transaction)
        const populatedSolution = await Solution.findById(solution._id)
          .populate('challenge')
          .populate('student')
          .session(session);

        if (!populatedSolution) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR,
            'Failed to retrieve solution after submission',
            true,
            'SOLUTION_RETRIEVAL_ERROR'
          );
        }

        return populatedSolution;
      });
    } catch (error) {
      logger.error(
        `Error submitting solution: ${error instanceof Error ? error.message : String(error)}`,
        { studentId, challengeId, error }
      );

      // Re-throw ApiError instances as-is
      if (error instanceof ApiError) throw error;

      // For any other errors, wrap in a generic ApiError
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to submit solution due to an unexpected error',
        true,
        'SOLUTION_SUBMISSION_ERROR'
      );
    }
  }

  /**
   * Get all solutions submitted by a student with enhanced filtering
   * @param studentId - The ID of the student
   * @param filters - Optional filters
   * @returns List of solutions with pagination info
   */
  async getStudentSolutions(
    studentId: string,
    filters: {
      status?: SolutionStatus;
      page?: number;
      limit?: number;
      sortBy?: string;
      sortOrder?: 'asc' | 'desc';
    }
  ): Promise<{ solutions: ISolution[]; total: number; page: number; limit: number }> {
    try {
      // Sanitize and validate the studentId
      const sanitizedStudentId = MongoSanitizer.validateObjectId(studentId, 'student');

      logger.debug(`Retrieving solutions for student ${sanitizedStudentId} with filters`, { filters });

      const session = await mongoose.startSession();
      session.startTransaction({ readConcern: { level: 'snapshot' } });

      try {
        // Sanitize pagination parameters
        const { status } = filters;
        const pageRaw = filters.page === undefined ? 1 : Number(filters.page);
        const limitRaw = filters.limit === undefined ? 10 : Number(filters.limit);

        // Validate and sanitize page/limit values
        const page = isNaN(pageRaw) || pageRaw < 1 ? 1 : Math.floor(pageRaw);
        const limit = isNaN(limitRaw) || limitRaw < 1 ? 10 : Math.min(Math.floor(limitRaw), 100);
        const skip = (page - 1) * limit;

        // Build safe query with $eq operator to prevent injection
        const query: Record<string, any> = {
          student: { $eq: new Types.ObjectId(sanitizedStudentId) }
        };

        // Safely add status filter if provided
        if (status) {
          // Validate status is a valid enum value
          if (!Object.values(SolutionStatus).includes(status)) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              `Invalid solution status. Allowed values: ${Object.values(SolutionStatus).join(', ')}`,
              true,
              'INVALID_STATUS'
            );
          }
          query.status = { $eq: status };
        }

        // Validate and sanitize sort parameters
        const allowedSortFields = ['createdAt', 'updatedAt', 'title', 'status', 'score'];
        let sortBy = 'updatedAt'; // Default sort field

        if (filters.sortBy && allowedSortFields.includes(filters.sortBy)) {
          sortBy = filters.sortBy;
        }

        // Sanitize sort order
        const sortOrder = filters.sortOrder === 'asc' ? 1 : -1;

        const sort: Record<string, 1 | -1> = {};
        sort[sortBy] = sortOrder;

        // Execute the query with sanitized parameters
        const [solutions, total] = await Promise.all([
          Solution.find(query)
            .populate('challenge', 'title description difficulty status deadline')
            .populate('reviewedBy', 'firstName lastName specialization')
            .populate('selectedBy', 'firstName lastName')
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .lean({ virtuals: true })
            .session(session),
          Solution.countDocuments(query).session(session)
        ]);

        await session.commitTransaction();
        session.endSession();

        return {
          solutions,
          total,
          page,
          limit
        };
      } catch (error) {
        await session.abortTransaction();
        session.endSession();
        throw error;
      }
    } catch (error) {
      logger.error(
        `Error retrieving student solutions: ${error instanceof Error ? error.message : String(error)}`,
        { studentId, filters: JSON.stringify(filters), error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve student solutions',
        true,
        'STUDENT_SOLUTIONS_RETRIEVAL_ERROR'
      );
    }
  }

  /**
  * Get all solutions for a specific challenge with comprehensive authorization and filtering
  * @param challengeId - Challenge ID
  * @param userId - User ID for authorization
  * @param userRole - User role for authorization
  * @param filters - Optional filters
  * @returns List of solutions with pagination info
  */
  async getChallengeSolutions(
    challengeId: string,
    userId: string,
    userRole: UserRole,
    filters: {
      status?: SolutionStatus;
      search?: string;  // Search in title or description
      score?: { min?: number; max?: number };  // Score range
      page?: number;
      limit?: number;
      sortBy?: string;
      sortOrder?: 'asc' | 'desc';
    } = {}
  ): Promise<{ solutions: ISolution[]; total: number; page: number; limit: number }> {
    try {
      // Sanitize challenge ID
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(challengeId, 'challenge');

      // Sanitize userId for use in authorization
      const sanitizedUserId = String(userId).trim();

      logger.debug(`Retrieving solutions for challenge ${sanitizedChallengeId}`, {
        userId: sanitizedUserId,
        userRole,
        filters
      });

      // Check if challenge exists with optimized query that includes needed fields
      const challenge = await Challenge.findById(sanitizedChallengeId)
        .select('company status claimedBy visibility allowedInstitutions')
        .lean();

      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      let architectProfileId: string | null = null;

      // Role-based Authorization logic with challenge claiming checks
      if (userRole === UserRole.COMPANY) {
        // Companies can only view their own challenges
        const companyId = await profileService.getCompanyProfileId(sanitizedUserId);

        if (challenge.company.toString() !== companyId) {
          logger.warn(`Unauthorized challenge access attempt by company ${companyId} for challenge ${sanitizedChallengeId}`, {
            companyId,
            challengeId: sanitizedChallengeId,
            actualOwner: challenge.company.toString()
          });

          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to view solutions for this challenge'
          );
        }
      } else if (userRole === UserRole.ARCHITECT) {
        // Get the architect's profile ID for comparison
        architectProfileId = await profileService.getArchitectProfileId(sanitizedUserId);

        // Verify challenge is in CLOSED status - architects can only view closed challenges
        if (challenge.status !== ChallengeStatus.CLOSED) {
          logger.warn(`Architect attempted to access solutions for non-closed challenge`, {
            architectId: architectProfileId,
            challengeId: sanitizedChallengeId,
            challengeStatus: challenge.status
          });

          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            `Architects can only view solutions for closed challenges. Current status: ${challenge.status}`
          );
        }

        // Check if the challenge has been claimed
        if (challenge.claimedBy) {
          // Check if the architect is the one who claimed this challenge
          if (challenge.claimedBy.toString() !== architectProfileId) {
            logger.warn(`Architect ${architectProfileId} attempted to access solutions for challenge claimed by another architect`, {
              architectId: architectProfileId,
              challengeId: sanitizedChallengeId,
              claimedBy: challenge.claimedBy.toString()
            });

            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'This challenge has been claimed by another architect'
            );
          }

          // Architect is authorized - this is the claiming architect
          logger.info(`Architect ${architectProfileId} accessing solutions for claimed challenge ${sanitizedChallengeId}`);
        } else {
          // Challenge is not claimed yet - log this access for audit purposes
          logger.info(`Architect ${architectProfileId} accessing solutions for unclaimed challenge ${sanitizedChallengeId}`);
        }
      } else if (userRole === UserRole.STUDENT) {
        // Students can only see public challenges or restricted challenges they are eligible for
        if (challenge.visibility === 'private') {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'This challenge is private and not accessible to students'
          );
        }

        if (challenge.visibility === ChallengeVisibility.ANONYMOUS && challenge.allowedInstitutions?.length) {
          const studentId = await profileService.getStudentProfileId(sanitizedUserId);
          const student = await StudentProfile.findById(studentId).select('university');

          if (!student) {
            throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
          }

          const isEligible = student.university &&
            challenge.allowedInstitutions.includes(student.university);

          if (!isEligible) {
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You are not eligible to view this challenge due to university restrictions'
            );
          }
        }
      }

      // Sanitize and validate all filter parameters
      // Get sanitized values with defaults
      const {
        status,
        search,
        score,
        page = 1,
        limit = 10,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = filters;

      // Start with a secure base query
      const query: Record<string, any> = {
        challenge: { $eq: new Types.ObjectId(sanitizedChallengeId) }
      };

      // Add status filter with validation and $eq operator
      if (status) {
        // Validate status is a valid enum value
        if (!Object.values(SolutionStatus).includes(status)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid solution status. Allowed values: ${Object.values(SolutionStatus).join(', ')}`,
            true,
            'INVALID_STATUS'
          );
        }
        query.status = { $eq: status };
      }

      // Add search filter with sanitization for NoSQL injection prevention
      if (search && search.trim()) {
        // Use MongoSanitizer for safe regex building
        const safeRegex = MongoSanitizer.buildSafeRegexCondition(search);

        query.$or = [
          { title: safeRegex },
          { description: safeRegex },
          { tags: safeRegex }
        ];
      }

      // Add score range filter with validation
      if (score) {
        // Use MongoSanitizer for safe numeric range
        const scoreRange = MongoSanitizer.buildNumericRangeCondition(
          score.min,
          score.max
        );

        if (Object.keys(scoreRange).length > 0) {
          query.score = scoreRange;
        }
      }

      // For architect-specific filtering based on claiming status
      if (userRole === UserRole.ARCHITECT && architectProfileId) {
        // If challenge is claimed, ensure only solutions the architect should review are visible
        if (challenge.claimedBy && challenge.claimedBy.toString() === architectProfileId) {
          // Architect should only see solutions that are submitted or ones they're already reviewing
          const architectSpecificStatuses = [
            SolutionStatus.SUBMITTED,
            SolutionStatus.UNDER_REVIEW,
            SolutionStatus.APPROVED,
            SolutionStatus.REJECTED
          ];

          if (status) {
            // If status filter is set, make sure it's in the list of allowed statuses
            if (!architectSpecificStatuses.includes(status)) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `Invalid status filter for architect. Allowed statuses: ${architectSpecificStatuses.join(', ')}`
              );
            }
            // Status filter is already set and valid
          } else {
            // If no status filter, default to showing all statuses the architect can see
            query.status = { $in: architectSpecificStatuses };
          }

          // Ensure architects only see solutions they are reviewing or should review
          query.$or = [
            { status: { $eq: SolutionStatus.SUBMITTED } }, // Not yet claimed solutions
            { reviewedBy: { $eq: new Types.ObjectId(architectProfileId) } } // Solutions being reviewed by this architect
          ];
        }
      }

      // Validate pagination parameters
      const validatedPage = Math.max(1, Number(page) || 1);
      const validatedLimit = Math.min(100, Math.max(1, Number(limit) || 10));
      const skip = (validatedPage - 1) * validatedLimit;

      // Validate and sanitize sort parameters using MongoSanitizer
      const allowedSortFields = ['createdAt', 'updatedAt', 'title', 'status', 'score'];
      const { sortBy: validatedSortBy, sortOrder: validatedSortOrder } =
        MongoSanitizer.validateSortParams(
          typeof sortBy === 'string' ? sortBy : 'createdAt',
          typeof sortOrder === 'string' ? sortOrder as 'asc' | 'desc' : 'desc',
          allowedSortFields
        );

      const sort: Record<string, 1 | -1> = {};
      sort[validatedSortBy] = validatedSortOrder;

      // Execute query with pagination using Promise.all for efficiency
      const [solutions, total] = await Promise.all([
        Solution.find(query)
          .populate('student', 'firstName lastName university')
          .populate('reviewedBy', 'firstName lastName specialization')
          .populate('selectedBy', 'firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(validatedLimit)
          .lean({ virtuals: true }),
        Solution.countDocuments(query)
      ]);

      logger.debug(`Retrieved ${solutions.length} solutions for challenge ${sanitizedChallengeId}`, {
        challengeId: sanitizedChallengeId,
        userRole,
        totalCount: total,
        page: validatedPage,
        limit: validatedLimit
      });

      return {
        solutions,
        total,
        page: validatedPage,
        limit: validatedLimit
      };

    } catch (error) {
      logger.error(
        `Error getting challenge solutions: ${error instanceof Error ? error.message : String(error)}`,
        {
          challengeId,
          userId,
          userRole,
          filters: JSON.stringify(filters),
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
        'Failed to retrieve challenge solutions',
        true,
        'SOLUTION_RETRIEVAL_ERROR'
      );
    }
  }

  /**
   * Get a solution by ID with enhanced security checks
   * @param solutionId - The ID of the solution
   * @param userId - The user ID requesting the solution (for authorization)
   * @param userRole - The role of the user (for role-based access control)
   * @returns The solution with all relevant populated fields
   * @throws ApiError if solution not found or user not authorized
   */
  async getSolutionById(
    solutionId: string,
    userId: string,
    userRole: UserRole
  ): Promise<ISolution> {
    try {
      // Sanitize and validate solution ID using MongoSanitizer
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');

      logger.debug(`Getting solution ${sanitizedSolutionId} for user ${userId} with role ${userRole}`);

      // Find the solution with all necessary populated fields
      const solution = await Solution.findById(sanitizedSolutionId)
        .populate({
          path: 'challenge',
          populate: {
            path: 'company',
            select: 'name logo location industry'
          }
        })
        .populate('student', 'firstName lastName university')
        .populate('reviewedBy', 'firstName lastName specialization')
        .populate('selectedBy', 'firstName lastName');

      if (!solution) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
      }

      // Normalize role for consistent comparison
      const role = String(userRole).toLowerCase();

      // Check permissions based on user role
      switch (role) {
        case 'student': {
          // Students can only view their own solutions
          const studentId = await profileService.getStudentProfileId(userId);

          // Handle both populated and non-populated student
          const solutionStudentId = solution.student instanceof mongoose.Types.ObjectId || typeof solution.student === 'string'
            ? solution.student.toString()
            : (solution.student as any)?._id?.toString();

          if (!solutionStudentId || solutionStudentId !== studentId) {
            logger.warn(`Student ${studentId} attempted to access solution ${sanitizedSolutionId} they don't own`, {
              attemptedAccessBy: studentId,
              actualOwner: solutionStudentId,
              requestedSolution: sanitizedSolutionId
            });

            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view this solution',
              true,
              'UNAUTHORIZED_SOLUTION_ACCESS'
            );
          }
          break;
        }
        case 'company': {
          // Companies can only view solutions for challenges they own
          if (!solution.challenge) {
            throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Solution has no associated challenge');
          }

          // Handle both populated and non-populated challenge
          const challenge = solution.challenge;
          let companyId: string | undefined;

          if (typeof challenge === 'string' || challenge instanceof mongoose.Types.ObjectId) {
            // If challenge is just an ID, we need to fetch it
            const fullChallenge = await Challenge.findById(challenge);
            companyId = fullChallenge?.company?.toString();
          } else {
            // If challenge is populated, extract company ID
            companyId = (challenge as any).company?._id?.toString() || (challenge as any).company?.toString();
          }

          if (!companyId) {
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Could not determine challenge owner');
          }

          // Get company profile ID from user ID
          const companyProfileId = await profileService.getCompanyProfileId(userId);

          if (companyId !== companyProfileId) {
            logger.warn(`Company ${companyProfileId} attempted to access solution ${sanitizedSolutionId} for challenge owned by ${companyId}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view this solution',
              true,
              'UNAUTHORIZED_SOLUTION_ACCESS'
            );
          }
          break;
        }

        case 'architect': {
          // Architects can only view solutions for closed challenges
          if (!solution.challenge) {
            throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Solution has no associated challenge');
          }

          // Handle both populated and non-populated challenge
          const challenge = solution.challenge;
          let challengeStatus: string | undefined;
          let challengeClaimedBy: string | undefined;

          if (typeof challenge === 'string' || challenge instanceof mongoose.Types.ObjectId) {
            // If challenge is just an ID, we need to fetch it
            const fullChallenge = await Challenge.findById(challenge);
            challengeStatus = fullChallenge?.status;
            challengeClaimedBy = fullChallenge?.claimedBy?.toString();
          } else {
            // If challenge is populated, extract status
            challengeStatus = (challenge as any).status;
            challengeClaimedBy = (challenge as any).claimedBy?.toString();
          }

          if (challengeStatus !== ChallengeStatus.CLOSED) {
            logger.warn(`Architect attempted to access solution for challenge with status ${challengeStatus}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'Architects can only view solutions for closed challenges'
            );
          }

          // Get architect profile ID
          const architectProfileId = await profileService.getArchitectProfileId(userId);

          // If challenge is claimed, verify this architect is the one who claimed it
          if (challengeClaimedBy && challengeClaimedBy !== architectProfileId) {
            logger.warn(`Architect ${architectProfileId} attempted to access solution for challenge claimed by ${challengeClaimedBy}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'This challenge has been claimed by another architect'
            );
          }
          break;
        }

        case 'admin':
          // Admins can view all solutions
          logger.debug(`Admin ${userId} accessing solution ${sanitizedSolutionId}`);
          break;

        default:
          // Unknown role
          logger.warn(`Unknown role ${role} attempted to access solution ${sanitizedSolutionId}`);
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to view this solution'
          );
      }

      return solution;
    } catch (error) {
      logger.error(
        `Error retrieving solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, userId, userRole, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve solution due to an unexpected error',
        true,
        'SOLUTION_RETRIEVAL_ERROR'
      );
    }
  }

  /**
   * Update a solution with transaction support
   * @param solutionId - The ID of the solution
   * @param studentId - The ID of the student
   * @param updateData - The update data
   * @returns The updated solution
   * @throws ApiError if validation fails or unauthorized
   */
  async updateSolution(
    solutionId: string,
    studentId: string,
    updateData: {
      title?: string;
      description?: string;
      submissionUrl?: string;
      tags?: string[];
    }
  ): Promise<ISolution> {
    try {
      // Sanitize and validate IDs using MongoSanitizer
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');
      const sanitizedStudentId = MongoSanitizer.validateObjectId(studentId, 'student');

      logger.debug(`Student ${sanitizedStudentId} attempting to update solution ${sanitizedSolutionId}`);

      return await this.withTransaction(async (session) => {
        // Get the solution using $eq operator to prevent injection
        const solution = await Solution.findById(sanitizedSolutionId).session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Verify ownership using $eq operator to prevent injection
        if (solution.student.toString() !== sanitizedStudentId) {
          logger.warn(`Student ${sanitizedStudentId} attempted to update solution ${sanitizedSolutionId} they don't own`);
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to update this solution'
          );
        }

        // Check if solution can be updated (only if in SUBMITTED status)
        if (solution.status !== SolutionStatus.SUBMITTED) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Cannot update solution with status: ${solution.status}. Only solutions in SUBMITTED status can be updated.`
          );
        }

        // Get the associated challenge to check deadline
        const challenge = await Challenge.findById(solution.challenge).session(session);

        if (!challenge) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Associated challenge not found');
        }

        // Check if challenge deadline has passed
        if (challenge.isDeadlinePassed()) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Challenge deadline has passed, solutions cannot be updated'
          );
        }

        // Validate update data
        if (Object.keys(updateData).length === 0) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'No update data provided');
        }

        const allowedFields = ['title', 'description', 'submissionUrl', 'tags'];
        const updates: Record<string, any> = {};

        // Filter updates to only allowed fields and sanitize values
        for (const field of allowedFields) {
          if (field in updateData && updateData[field as keyof typeof updateData] !== undefined) {
            const value = updateData[field as keyof typeof updateData];

            // Sanitize based on field type
            if (field === 'tags' && Array.isArray(value)) {
              // Sanitize each tag 
              updates[field] = (value as string[]).map(tag => String(tag).trim());
            } else if (typeof value === 'string') {
              // Sanitize string values
              updates[field] = String(value).trim();
            }
          }
        }

        // Validate required fields if they are being updated
        if ('title' in updates && (!updates.title || typeof updates.title !== 'string')) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Title is required and must be a string');
        }

        if ('description' in updates && (!updates.description || typeof updates.description !== 'string')) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Description is required and must be a string');
        }

        if ('submissionUrl' in updates && (!updates.submissionUrl || typeof updates.submissionUrl !== 'string')) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Submission URL is required and must be a string');
        }

        if ('tags' in updates && !Array.isArray(updates.tags)) {
          throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Tags must be an array of strings');
        }

        // Update the solution with transaction support
        solution.set(updates);
        await solution.save({ session });

        logger.info(
          `Student ${sanitizedStudentId} successfully updated solution ${sanitizedSolutionId}`,
          {
            studentId: sanitizedStudentId,
            solutionId: sanitizedSolutionId,
            updatedFields: Object.keys(updates)
          }
        );

        // Return the updated solution (populated within transaction)
        const populatedSolution = await Solution.findById(sanitizedSolutionId)
          .populate('challenge')
          .populate('student')
          .session(session);

        if (!populatedSolution) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR,
            'Failed to retrieve solution after updating',
            true,
            'SOLUTION_RETRIEVAL_ERROR'
          );
        }

        return populatedSolution;
      });
    } catch (error) {
      logger.error(
        `Error updating solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, studentId, updateData, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to update solution due to an unexpected error',
        true,
        'SOLUTION_UPDATE_ERROR'
      );
    }
  }

  /**
   * Validate review data
   * @param reviewData - The review data to validate
   * @returns Validated review data
   * @throws ApiError if validation fails
   */
  validateReviewData(
    reviewData: {
      status: SolutionStatus;
      feedback: string;
      score?: number;
    }
  ): { status: SolutionStatus.APPROVED | SolutionStatus.REJECTED; feedback: string; score?: number } {
    try {
      // Validate status
      if (!reviewData.status) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Status is required');
      }

      // Ensure status is a string and validate against allowed values
      const status = String(reviewData.status);
      if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(status as SolutionStatus)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Status must be either approved or rejected'
        );
      }

      // Validate feedback
      if (!reviewData.feedback || typeof reviewData.feedback !== 'string' || reviewData.feedback.trim().length === 0) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Feedback is required');
      }

      // Validate score if provided
      let sanitizedScore: number | undefined = undefined;
      if (reviewData.score !== undefined) {
        const score = Number(reviewData.score);
        if (isNaN(score) || score < 0 || score > 100) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Score must be between 0 and 100'
          );
        }
        sanitizedScore = score;
      }

      // Additional validation for specific status types
      if (status === SolutionStatus.APPROVED && sanitizedScore === undefined) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Score is required when approving a solution'
        );
      }

      return {
        status: status as SolutionStatus.APPROVED | SolutionStatus.REJECTED,
        feedback: reviewData.feedback,
        score: sanitizedScore
      };
    } catch (error) {
      logger.error(`Error validating review data: ${error instanceof Error ? error.message : 'Unknown error'}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid review data');
    }
  }

  /**
   * Claim a solution for review by an architect with transaction support
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect
   * @returns The updated solution
   */
  async claimSolutionForReview(
    solutionId: string,
    architectId: string
  ): Promise<ISolution> {
    try {
      // Sanitize and validate IDs using MongoSanitizer
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');
      const sanitizedArchitectId = MongoSanitizer.validateObjectId(architectId, 'architect');

      logger.debug(`Architect ${sanitizedArchitectId} attempting to claim solution ${sanitizedSolutionId} for review`);

      return await this.withTransaction(async (session) => {
        // Find the solution using sanitized ID
        const solution = await Solution.findById(sanitizedSolutionId).session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Separately fetch the latest challenge data to ensure it's current
        const challenge = await Challenge.findById(solution.challenge).session(session);

        if (!challenge) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Associated challenge not found');
        }

        // Check if the challenge is closed (only closed challenges can be reviewed)
        if (challenge.status !== ChallengeStatus.CLOSED) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Solutions can only be claimed for challenges with status 'closed'. ` +
            `Current challenge status: ${challenge.status}.`,
            true,
            'INVALID_CHALLENGE_STATUS'
          );
        }

        // Check if solution is already claimed by another architect using $eq operator
        if (solution.reviewedBy && solution.reviewedBy.toString() !== sanitizedArchitectId) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            'This solution has already been claimed by another architect',
            true,
            'SOLUTION_ALREADY_CLAIMED'
          );
        }

        // Use the state transition manager to validate and apply the transition
        if (solution.status !== SolutionStatus.SUBMITTED) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            `Invalid state transition from ${solution.status} to ${SolutionStatus.UNDER_REVIEW}. Only 'submitted' solutions can be claimed.`
          );
        }

        // Apply the state transition with sanitized ID
        solution.status = SolutionStatus.UNDER_REVIEW;
        solution.reviewedBy = new Types.ObjectId(sanitizedArchitectId);
        solution.updatedAt = new Date();

        await solution.save({ session });

        logger.info(`Solution ${sanitizedSolutionId} claimed for review by architect ${sanitizedArchitectId}`);

        // Populate within transaction
        const populatedSolution = await Solution.findById(solution._id)
          .populate('challenge')
          .populate('student')
          .populate('reviewedBy')
          .session(session);

        if (!populatedSolution) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR,
            'Failed to retrieve solution after updating',
            true,
            'SOLUTION_RETRIEVAL_ERROR'
          );
        }

        return populatedSolution;
      });
    } catch (error) {
      logger.error(
        `Error claiming solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, architectId, error }
      );

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
   * Review a solution (approve/reject) with transaction support
   * @param solutionId - The ID of the solution
   * @param architectId - The ID of the architect
   * @param reviewData - The review data
   * @returns The updated solution
   */
  async reviewSolution(
    solutionId: string,
    architectId: string,
    reviewData: {
      status: SolutionStatus;
      feedback: string;
      score?: number;
    }
  ): Promise<ISolution> {
    try {
      // Sanitize and validate IDs using MongoSanitizer
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');
      const sanitizedArchitectId = MongoSanitizer.validateObjectId(architectId, 'architect');

      logger.debug(`Architect ${sanitizedArchitectId} attempting to review solution ${sanitizedSolutionId}`, {
        reviewStatus: reviewData.status
      });

      // Validate review data
      const validatedData = this.validateReviewData(reviewData);

      // Sanitize feedback
      const sanitizedFeedback = String(validatedData.feedback).trim();

      return await this.withTransaction(async (session) => {
        // Find the solution using sanitized ID
        const solution = await Solution.findById(sanitizedSolutionId)
          .populate('challenge')
          .session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Verify reviewer is the claiming architect using $eq operator to prevent injection
        if (!solution.reviewedBy || solution.reviewedBy.toString() !== sanitizedArchitectId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'Only the architect who claimed this solution can review it'
          );
        }

        // For approvals, check if challenge has reached approval limit
        if (validatedData.status === SolutionStatus.APPROVED && solution.challenge) {
          const challengeId = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
            ? solution.challenge
            : solution.challenge._id;

          // Use findOneAndUpdate with conditional update instead of separate operations
          const challengeUpdate = await Challenge.findOneAndUpdate(
            {
              _id: { $eq: challengeId },
              $or: [
                { maxApprovedSolutions: { $exists: false } },
                { maxApprovedSolutions: null },
                { approvedSolutionsCount: { $lt: "$maxApprovedSolutions" } }
              ]
            },
            { $inc: { approvedSolutionsCount: 1 } },
            { session, new: true, runValidators: true }
          );

          if (!challengeUpdate) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              'Maximum number of approved solutions has been reached for this challenge',
              true,
              'MAX_APPROVALS_REACHED'
            );
          }
        }

        // Check if the challenge's review deadline has passed
        const challenge = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
          ? await Challenge.findById(solution.challenge).session(session)
          : solution.challenge;

        if (!challenge) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Associated challenge not found');
        }

        // Verify solution is in the correct state for review
        if (solution.status !== SolutionStatus.UNDER_REVIEW) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid state transition from ${solution.status} to ${validatedData.status}. Only solutions in 'under_review' status can be reviewed.`
          );
        }

        // For approvals, check if challenge has reached approval limit
        if (validatedData.status === SolutionStatus.APPROVED && solution.challenge) {
          const challengeObj = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
            ? await Challenge.findById(solution.challenge).session(session)
            : solution.challenge;

          if (challengeObj && challengeObj.maxApprovedSolutions && challengeObj.approvedSolutionsCount >= challengeObj.maxApprovedSolutions) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              `Maximum number of approved solutions (${challengeObj.maxApprovedSolutions}) has been reached for this challenge`
            );
          }

          // If approving a solution, increment the approvedSolutionsCount on the challenge
          const challengeId = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
            ? solution.challenge
            : solution.challenge._id;

          await Challenge.findByIdAndUpdate(
            challengeId,
            { $inc: { approvedSolutionsCount: 1 } },
            { session }
          );
        }

        // Apply the state change with sanitized data
        solution.status = validatedData.status;
        solution.feedback = sanitizedFeedback;
        if (validatedData.score !== undefined) {
          // Ensure score is a valid number within allowed range
          const sanitizedScore = Math.min(Math.max(0, Number(validatedData.score)), 100);
          solution.score = sanitizedScore;
        }
        solution.reviewedAt = new Date();

        await solution.save({ session });

        logger.info(
          `Solution ${sanitizedSolutionId} ${validatedData.status === SolutionStatus.APPROVED ? 'approved' : 'rejected'} ` +
          `by architect ${sanitizedArchitectId}`
        );

        // OPTIMIZATION: Use a single query with specific field projection
        const populatedSolution = await Solution.findById(solution._id)
          .populate([
            { path: 'challenge', select: 'title description company status' },
            { path: 'student', select: 'firstName lastName email university' },
            { path: 'reviewedBy', select: 'firstName lastName specialization' }
          ])
          .session(session);

        if (!populatedSolution) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR,
            'Failed to retrieve solution after updating',
            true,
            'SOLUTION_RETRIEVAL_ERROR'
          );
        }

        return populatedSolution;
      });
    } catch (error) {
      logger.error(
        `Error reviewing solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, architectId, reviewData: JSON.stringify(reviewData), error }
      );

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
   * Select a solution as winning (by company) with transaction support
   * @param solutionId - The ID of the solution
   * @param companyId - The ID of the company
   * @param selectionData - Optional data about the selection (feedback, reason)
   * @returns The updated solution
   */
  async selectSolutionAsWinner(
    solutionId: string,
    companyId: string,
    selectionData?: {
      companyFeedback?: string;
      selectionReason?: string;
    }
  ): Promise<ISolution> {
    try {
      // Sanitize and validate IDs using MongoSanitizer
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(companyId, 'company');

      logger.debug(`Company ${sanitizedCompanyId} attempting to select solution ${sanitizedSolutionId} as winner`);

      return await this.withTransaction(async (session) => {
        // Find the solution using sanitized ID
        const solution = await Solution.findById(sanitizedSolutionId)
          .populate({
            path: 'challenge',
            populate: {
              path: 'company'
            }
          })
          .session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Verify solution is in APPROVED state
        if (solution.status !== SolutionStatus.APPROVED) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid state transition from ${solution.status} to ${SolutionStatus.SELECTED}. Only approved solutions can be selected as winners.`
          );
        }

        // Verify company owns the challenge
        if (!solution.challenge || typeof solution.challenge === 'string') {
          throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Challenge data not available');
        }

        // Handle both ObjectId and IChallenge types for challenge
        const challenge = solution.challenge instanceof mongoose.Types.ObjectId
          ? await Challenge.findById(solution.challenge).session(session)
          : solution.challenge;

        if (!challenge || !challenge.company) {
          throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Challenge company data not available');
        }

        const challengeCompanyId = typeof challenge.company === 'string'
          ? challenge.company
          : (challenge.company as any)._id?.toString();

        if (challengeCompanyId !== sanitizedCompanyId) {
          logger.warn(`Company ${sanitizedCompanyId} attempted to select a solution for challenge owned by ${challengeCompanyId}`);
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to select a solution for this challenge'
          );
        }

        // Verify challenge is in appropriate status for selection
        if (typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId) {
          // If challenge is just an ID, we need to fetch it
          const fullChallenge = await Challenge.findById(solution.challenge).session(session);
          if (!fullChallenge) {
            throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
          }
          if (fullChallenge.status !== ChallengeStatus.CLOSED) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              `Solutions can only be selected for challenges with status 'closed'. ` +
              `Current challenge status: ${fullChallenge.status}.`
            );
          }
        } else {
          // It's a populated IChallenge object
          const challengeObj = solution.challenge as any; // Type assertion to access properties
          if (challengeObj.status !== ChallengeStatus.CLOSED) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              `Solutions can only be selected for challenges with status 'closed'. ` +
              `Current challenge status: ${challengeObj.status}.`
            );
          }
        }

        // Apply the status change with sanitized company ID
        solution.status = SolutionStatus.SELECTED;
        solution.selectedAt = new Date();
        solution.selectedBy = new Types.ObjectId(sanitizedCompanyId);

        // Add company feedback and selection reason if provided
        if (selectionData?.companyFeedback) {
          solution.companyFeedback = selectionData.companyFeedback;
        }

        if (selectionData?.selectionReason) {
          solution.selectionReason = selectionData.selectionReason;
        }

        await solution.save({ session });

        // Update challenge status to COMPLETED if not already
        const challengeId = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
          ? solution.challenge
          : solution.challenge._id;

        const challengeStatus = typeof solution.challenge === 'string' || solution.challenge instanceof mongoose.Types.ObjectId
          ? undefined  // We don't know the status if it's just an ID
          : solution.challenge.status;

        if (challengeStatus !== ChallengeStatus.COMPLETED) {
          await Challenge.findByIdAndUpdate(
            { _id: { $eq: challengeId } }, // Use $eq operator for safety
            {
              $set: {
                status: ChallengeStatus.COMPLETED,
                completedAt: new Date()
              }
            },
            { session, new: true }
          );
        }

        logger.info(`Solution ${sanitizedSolutionId} selected as winner by company ${sanitizedCompanyId}`);

        // Populate within transaction
        const populatedSolution = await Solution.findById(solution._id)
          .populate('challenge')
          .populate('student')
          .populate('reviewedBy')
          .populate('selectedBy')
          .session(session);

        if (!populatedSolution) {
          throw new ApiError(
            HTTP_STATUS.INTERNAL_SERVER_ERROR,
            'Failed to retrieve solution after selection',
            true,
            'SOLUTION_RETRIEVAL_ERROR'
          );
        }

        return populatedSolution;
      });
    } catch (error) {
      logger.error(
        `Error selecting solution as winner: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, companyId, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to select solution as winner',
        true,
        'SOLUTION_SELECTION_ERROR'
      );
    }
  }

  /**
   * Get solutions reviewed by an architect with pagination
   * @param architectId - Architect profile ID
   * @param options - Pagination and filtering options
   * @returns List of solutions with pagination info
   */
  async getArchitectReviews(
    architectId: string,
    options: PaginationOptions = {}
  ): Promise<PaginationResult<ISolution>> {
    try {
      // Sanitize and validate architect ID
      const sanitizedArchitectId = MongoSanitizer.validateObjectId(architectId, 'architect');

      logger.debug(`Retrieving reviews for architect ${sanitizedArchitectId}`, { options });

      // Sanitize pagination parameters
      const sanitizedOptions = this.validateAndSanitizePaginationOptions(options);
      const { status, page = 1, limit = 10 } = sanitizedOptions;
      const skip = (Number(page) - 1) * Number(limit);

      // Build match criteria with proper sanitization
      const matchCriteria: Record<string, any> = {
        reviewedBy: new Types.ObjectId(sanitizedArchitectId)
      };

      // Add status filter if provided (after validation)
      if (status) {
        // Validate status is a valid enum value
        if (!Object.values(SolutionStatus).includes(status as SolutionStatus)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid solution status. Allowed values: ${Object.values(SolutionStatus).join(', ')}`,
            true,
            'INVALID_STATUS'
          );
        }
        matchCriteria.status = { $eq: status };
      }

      // Define pipeline stages with explicit typing and sanitization
      const pipeline: PipelineStage[] = [
        { $match: matchCriteria },
        { $sort: { reviewedAt: -1 } },
        {
          $facet: {
            totalCount: [
              { $count: 'count' }
            ],
            paginatedResults: [
              { $skip: skip },
              { $limit: Number(limit) },
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
              {
                $project: {
                  _id: 1,
                  status: 1,
                  feedback: 1,
                  score: 1,
                  reviewedAt: 1,
                  'challenge._id': 1,
                  'challenge.title': 1,
                  'challenge.status': 1,
                  'student._id': 1,
                  'student.firstName': 1,
                  'student.lastName': 1
                }
              }
            ]
          }
        }
      ];

      // Execute the aggregate with sanitized pipeline
      const results = await Solution.aggregate(pipeline);

      const total = results[0]?.totalCount[0]?.count || 0;
      const data = results[0]?.paginatedResults || [];

      logger.debug(`Retrieved ${data.length} reviews for architect ${sanitizedArchitectId}`, {
        totalReviews: total,
        page,
        limit
      });

      // Return object structure matching PaginationResult interface
      return {
        data,
        page: Number(page),
        limit: Number(limit),
        total,
        totalPages: Math.ceil(total / Number(limit)),
        hasNextPage: Number(page) * Number(limit) < total,
        hasPrevPage: Number(page) > 1
      };
    } catch (error) {
      logger.error(
        `Error retrieving architect reviews: ${error instanceof Error ? error.message : String(error)}`,
        { architectId, options, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve architect reviews',
        true,
        'ARCHITECT_REVIEWS_ERROR'
      );
    }
  }

  /**
   * Validate and sanitize pagination options
   * @param options - Raw pagination options
   * @returns Sanitized pagination options
   */
  private validateAndSanitizePaginationOptions(options: PaginationOptions): PaginationOptions {
    const sanitizedOptions: PaginationOptions = {};

    // Sanitize page
    if (options.page !== undefined) {
      const page = Number(options.page);
      if (isNaN(page) || page < 1) {
        sanitizedOptions.page = 1; // Default to first page if invalid
      } else {
        sanitizedOptions.page = Math.floor(page); // Ensure it's an integer
      }
    } else {
      sanitizedOptions.page = 1; // Default
    }

    // Sanitize limit
    if (options.limit !== undefined) {
      const limit = Number(options.limit);
      if (isNaN(limit) || limit < 1) {
        sanitizedOptions.limit = 10; // Default limit if invalid
      } else {
        // Cap at 100 for performance reasons
        sanitizedOptions.limit = Math.min(Math.floor(limit), 100);
      }
    } else {
      sanitizedOptions.limit = 10; // Default
    }

    // Sanitize status if provided
    if (options.status) {
      // Options.status will be validated in the method that uses it
      sanitizedOptions.status = options.status;
    }

    // Sanitize sort options
    if (options.sortBy) {
      // Allow only certain fields for sorting
      const allowedSortFields = ['createdAt', 'updatedAt', 'reviewedAt', 'status', 'score'];
      if (allowedSortFields.includes(options.sortBy)) {
        sanitizedOptions.sortBy = options.sortBy;
      } else {
        sanitizedOptions.sortBy = 'reviewedAt'; // Default
      }
    } else {
      sanitizedOptions.sortBy = 'reviewedAt'; // Default
    }

    // Sanitize sort order
    if (options.sortOrder && ['asc', 'desc'].includes(options.sortOrder)) {
      sanitizedOptions.sortOrder = options.sortOrder;
    } else {
      sanitizedOptions.sortOrder = 'desc'; // Default
    }

    return sanitizedOptions;
  }

  /**
   * Submit a solution to the AI evaluation pipeline and then to architect review
   * This method serves as the main integration point between AI evaluation and architect review
   * @param solutionId - ID of the solution to process
   * @returns The updated solution with evaluation results
   */
  async submitSolutionForAIEvaluationAndArchitectReview(
    solutionId: string
  ): Promise<ISolution> {
    try {
      logger.info(`Starting AI evaluation and architect review workflow for solution`, {
        solutionId
      });

      // Validate solution ID
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Get solution with challenge details
      const solution = await Solution.findById(sanitizedSolutionId)
        .populate('challenge')
        .populate('student');

      if (!solution) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Solution not found',
          true,
          'SOLUTION_NOT_FOUND'
        );
      }

      // Only process solutions in SUBMITTED status
      if (solution.status !== SolutionStatus.SUBMITTED) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot process solution in ${solution.status} status, must be in SUBMITTED status`,
          true,
          'INVALID_SOLUTION_STATUS'
        );
      }

      // Get the evaluation pipeline controller
      const { evaluationPipelineController } = await import('./ai/EvaluationPipelineController');

      // Set the appropriate number of evaluation passes based on challenge difficulty
      const challengeObj = solution.challenge as IChallenge;
      let maxPasses = 1; // Default for standard evaluation

      if (challengeObj && challengeObj.difficulty) {
        // More passes for more difficult challenges
        if (challengeObj.difficulty === ChallengeDifficulty.INTERMEDIATE) {
          maxPasses = 2;
        } else if (challengeObj.difficulty === ChallengeDifficulty.ADVANCED ||
          challengeObj.difficulty === ChallengeDifficulty.EXPERT) {
          maxPasses = 3;
        }
      }

      logger.info(`Executing evaluation pipeline with ${maxPasses} passes`, {
        solutionId: solution._id?.toString(),
        challengeId: challengeObj?._id?.toString(),
        difficulty: challengeObj?.difficulty
      });

      // Run the evaluation pipeline with appropriate number of passes
      const pipelineResult = await evaluationPipelineController.executeIterativePipeline(
        solution,
        maxPasses
      );

      // Process and format solution for architect review
      const preparedSolution = evaluationPipelineController.prepareSolutionForArchitectReview(
        solution,
        pipelineResult
      );

      // Determine if the solution should go to architect review based on final decision
      let newStatus = SolutionStatus.SUBMITTED;

      if (pipelineResult.finalDecision === EvaluationDecision.FAIL) {
        // If AI has determined the solution is clearly failing, mark it as rejected
        // Architects can still review these in their dashboard if needed
        newStatus = SolutionStatus.REJECTED;

        // Log the automatic rejection
        logger.info(`Solution automatically rejected by AI evaluation`, {
          solutionId: this.getDocumentId(solution),
          score: solution.score,
          finalDecision: pipelineResult.finalDecision
        });
      } else {
        // For PASS or REVIEW decisions, keep as SUBMITTED for architect review
        newStatus = SolutionStatus.SUBMITTED;

        // Log the submission to architect review
        logger.info(`Solution ready for architect review after AI evaluation`, {
          solutionId: this.getDocumentId(solution),
          score: solution.score,
          finalDecision: pipelineResult.finalDecision
        });
      }

      // Update solution with evaluation results and status
      preparedSolution.status = newStatus;

      // Save the updated solution
      await preparedSolution.save();

      return preparedSolution;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error(`Error in AI evaluation and architect review workflow`, {
        solutionId,
        error: errorMessage,
        stack: errorStack
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        `Error processing solution evaluation: ${errorMessage}`,
        true,
        'EVALUATION_PROCESSING_ERROR'
      );
    }
  }

  /**
   * Process solutions for a specific challenge in bulk
   * This will evaluate all solutions for the challenge and prepare them for architect review
   * @param challengeId - ID of the challenge
   * @returns Summary of processed solutions
   */
  async processChallengeForArchitectReview(
    challengeId: string
  ): Promise<{
    totalSolutions: number;
    processedSolutions: number;
    failedSolutions: number;
    processingTimeMs: number;
  }> {
    try {
      const startTime = Date.now();
      logger.info(`Processing all solutions for challenge`, { challengeId });

      // Validate challenge ID
      const sanitizedChallengeId = MongoSanitizer.validateObjectId(challengeId, 'challenge');

      // Find all submitted solutions for this challenge
      const solutions = await Solution.find({
        challenge: sanitizedChallengeId,
        status: SolutionStatus.SUBMITTED
      });

      logger.info(`Found ${solutions.length} submitted solutions for challenge`, {
        challengeId,
        solutionCount: solutions.length
      });

      // Process solutions in parallel using Promise.all
      // Limit concurrency to avoid overwhelming the AI services
      const batchSize = 5; // Process 5 solutions at a time
      const results = {
        totalSolutions: solutions.length,
        processedSolutions: 0,
        failedSolutions: 0,
        processingTimeMs: 0
      };

      // Process in batches
      for (let i = 0; i < solutions.length; i += batchSize) {
        const batch = solutions.slice(i, i + batchSize);

        // Process batch in parallel
        const batchResults = await Promise.allSettled(
          batch.map((solution: ISolution) =>
            this.submitSolutionForAIEvaluationAndArchitectReview(
              (solution._id as mongoose.Types.ObjectId | string).toString()
            )
          )
        );

        // Count successes and failures
        batchResults.forEach(result => {
          if (result.status === 'fulfilled') {
            results.processedSolutions++;
          } else {
            results.failedSolutions++;
            logger.error(`Failed to process solution in batch`, {
              challengeId,
              error: result.reason instanceof Error ? result.reason.message : String(result.reason)
            });
          }
        });

        // Log batch progress
        logger.info(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(solutions.length / batchSize)}`, {
          challengeId,
          batchSize: batch.length,
          successCount: batchResults.filter(r => r.status === 'fulfilled').length,
          failureCount: batchResults.filter(r => r.status === 'rejected').length
        });
      }

      // Update processing time
      results.processingTimeMs = Date.now() - startTime;

      // Update challenge status to CLOSED if all solutions are processed
      if (results.processedSolutions > 0) {
        const challenge = await Challenge.findById(sanitizedChallengeId);
        if (challenge && challenge.status !== ChallengeStatus.CLOSED) {
          challenge.status = ChallengeStatus.CLOSED;
          await challenge.save();

          logger.info(`Challenge status updated to CLOSED`, { challengeId });
        }
      }

      logger.info(`Challenge processing completed`, {
        challengeId,
        ...results
      });

      return results;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error processing challenge solutions`, {
        challengeId,
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        `Error processing challenge solutions: ${errorMessage}`,
        true,
        'CHALLENGE_PROCESSING_ERROR'
      );
    }
  }
}

export const solutionService = new SolutionService();