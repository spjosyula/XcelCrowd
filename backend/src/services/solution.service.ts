import mongoose, { Types } from 'mongoose';
import Solution from '../models/Solution';
import Challenge from '../models/Challenge';
import StudentProfile from '../models/StudentProfile';
import { profileService } from './profile.service';
import { PipelineStage } from 'mongoose';
import {
  HTTP_STATUS,
  SolutionStatus,
  ChallengeStatus,
  ChallengeVisibility,
  UserRole,
  ISolution,
  IStudentProfile,
  IChallenge
} from '../models/interfaces';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { isValidTransition, transitionSolutionState } from '../utils/solution-state-manager';
import { executePaginatedQuery, PaginationOptions, PaginationResult } from '../utils/paginationUtils';
import { validateObjectId } from '../utils/mongoUtils';
import { ArchitectProfile } from '../models';
import { BaseService } from './BaseService';


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
      // Validate IDs to fail fast
      if (!Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
      }
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

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

      // Log submission attempt
      logger.info(`Student ${studentId} attempting to submit solution for challenge ${challengeId}`);

      // If idempotencyKey provided, check for existing submission with this key
      if (idempotencyKey) {
        const existingSolutionWithKey = await Solution.findOne({
          idempotencyKey,
          student: studentId
        }).populate('challenge').populate('student');
        
        if (existingSolutionWithKey) {
          logger.info(`Found existing solution with idempotency key ${idempotencyKey}`, {
            studentId,
            solutionId: existingSolutionWithKey._id
          });
          return existingSolutionWithKey;
        }
      }

      return await this.withTransaction(async (session) => {
        // Increment the current participants count atomically with transaction support
        const updatedChallenge = await Challenge.findByIdAndUpdate(
          challengeId,
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
          const student = await StudentProfile.findById(studentId).session(session);
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

        // Check for duplicate submission
        const existingSolution = await Solution.findOne({
          student: studentId,
          challenge: challengeId
        }).session(session);

        if (existingSolution) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            'You have already submitted a solution for this challenge',
            true,
            'DUPLICATE_SUBMISSION'
          );
        }

        // Create the solution
        const solution = new Solution({
          student: studentId,
          challenge: challengeId,
          title: solutionData.title,
          description: solutionData.description,
          submissionUrl: solutionData.submissionUrl,
          status: SolutionStatus.SUBMITTED,
          ...(solutionData.tags && { tags: solutionData.tags }),
          ...(idempotencyKey && { idempotencyKey })
        });

        await solution.save({ session });

        logger.info(
          `Student ${studentId} successfully submitted solution ${solution._id} for challenge ${challengeId}`,
          {
            studentId,
            challengeId,
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
      if (!Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
      }

      logger.debug(`Retrieving solutions for student ${studentId} with filters`, { filters });

      const session = await mongoose.startSession();
      session.startTransaction({ readConcern: { level: 'snapshot' } });
      
      try {
        const { status, page = 1, limit = 10, sortBy = 'updatedAt', sortOrder = 'desc' } = filters;
        const query: Record<string, any> = { student: new Types.ObjectId(studentId) };
        if (status) query.status = status;
        
        const skip = (Number(page) - 1) * Number(limit);
        const sort: Record<string, 1 | -1> = {};
        sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

        const [solutions, total] = await Promise.all([
          Solution.find(query)
            .populate('challenge', 'title description difficulty status deadline')
            .populate('reviewedBy', 'firstName lastName specialization')
            .populate('selectedBy', 'firstName lastName')
            .sort(sort)
            .skip(skip)
            .limit(Number(limit))
            .lean({ virtuals: true })
            .session(session),
          Solution.countDocuments(query).session(session)
        ]);

        await session.commitTransaction();
        session.endSession();
        
        return {
          solutions,
          total,
          page: Number(page),
          limit: Number(limit)
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
      // Validate challenge ID
      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      logger.debug(`Retrieving solutions for challenge ${challengeId}`, {
        userId,
        userRole,
        filters
      });

      // Check if challenge exists with optimized query that includes needed fields
      const challenge = await Challenge.findById(challengeId)
        .select('company status claimedBy visibility allowedInstitutions')
        .lean();

      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      let architectProfileId: string | null = null;

      // Role-based Authorization logic with challenge claiming checks
      if (userRole === UserRole.COMPANY) {
        // Companies can only view their own challenges
        const companyId = await profileService.getCompanyProfileId(userId);

        if (challenge.company.toString() !== companyId) {
          logger.warn(`Unauthorized challenge access attempt by company ${companyId} for challenge ${challengeId}`, {
            companyId,
            challengeId,
            actualOwner: challenge.company.toString()
          });

          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to view solutions for this challenge'
          );
        }
      } else if (userRole === UserRole.ARCHITECT) {
        // Get the architect's profile ID for comparison
        architectProfileId = await profileService.getArchitectProfileId(userId);

        // Verify challenge is in CLOSED status - architects can only view closed challenges
        if (challenge.status !== ChallengeStatus.CLOSED) {
          logger.warn(`Architect attempted to access solutions for non-closed challenge`, {
            architectId: architectProfileId,
            challengeId,
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
              challengeId,
              claimedBy: challenge.claimedBy.toString()
            });

            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'This challenge has been claimed by another architect'
            );
          }

          // Architect is authorized - this is the claiming architect
          logger.info(`Architect ${architectProfileId} accessing solutions for claimed challenge ${challengeId}`);
        } else {
          // Challenge is not claimed yet - log this access for audit purposes
          logger.info(`Architect ${architectProfileId} accessing solutions for unclaimed challenge ${challengeId}`);
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
          const studentId = await profileService.getStudentProfileId(userId);
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

      // Build query based on filters with proper type safety
      const {
        status,
        search,
        score,
        page = 1,
        limit = 10,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = filters;

      const query: Record<string, any> = { challenge: new Types.ObjectId(challengeId) };

      // Add status filter if specified
      if (status) {
        query.status = status;
      }

      // Add search filter if specified
      if (search && search.trim()) {
        query.$or = [
          { title: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
          { tags: { $regex: search, $options: 'i' } }
        ];
      }

      // Add score range filter if specified
      if (score) {
        query.score = {};
        if (score.min !== undefined) query.score.$gte = score.min;
        if (score.max !== undefined) query.score.$lte = score.max;
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
            { status: SolutionStatus.SUBMITTED }, // Not yet claimed solutions
            { reviewedBy: new Types.ObjectId(architectProfileId) } // Solutions being reviewed by this architect
          ];
        }
      }

      // Calculate pagination parameters
      const skip = (Number(page) - 1) * Number(limit);

      // Create sort object with type safety
      const sort: Record<string, 1 | -1> = {};
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute query with pagination using Promise.all for efficiency
      const [solutions, total] = await Promise.all([
        Solution.find(query)
          .populate('student', 'firstName lastName university')
          .populate('reviewedBy', 'firstName lastName specialization')
          .populate('selectedBy', 'firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(Number(limit))
          .lean({ virtuals: true }), // Use lean for better performance
        Solution.countDocuments(query)
      ]);

      logger.debug(`Retrieved ${solutions.length} solutions for challenge ${challengeId}`, {
        challengeId,
        userRole,
        totalCount: total,
        page,
        limit
      });

      return {
        solutions,
        total,
        page: Number(page),
        limit: Number(limit)
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
      // Validate solution ID
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid solution ID format',
          true,
          'INVALID_ID_FORMAT'
        );
      }

      logger.debug(`Getting solution ${solutionId} for user ${userId} with role ${userRole}`);

      // Find the solution with all necessary populated fields
      const solution = await Solution.findById(solutionId)
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
      const role = userRole.toLowerCase();

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
            logger.warn(`Student ${studentId} attempted to access solution ${solutionId} they don't own`, {
              attemptedAccessBy: studentId,
              actualOwner: solutionStudentId,
              requestedSolution: solutionId
            });

            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view this solution',
              true,
              'UNAUTHORIZED_SOLUTION_ACCESS'
            );
          }
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
            logger.warn(`Company ${companyProfileId} attempted to access solution ${solutionId} for challenge owned by ${companyId}`);
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
          logger.debug(`Admin ${userId} accessing solution ${solutionId}`);
          break;

        default:
          // Unknown role
          logger.warn(`Unknown role ${role} attempted to access solution ${solutionId}`);
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
      // Validate IDs upfront to fail fast
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
      }

      logger.debug(`Student ${studentId} attempting to update solution ${solutionId}`);

      return await this.withTransaction(async (session) => {
        // Get the solution
        const solution = await Solution.findById(solutionId).session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Verify ownership
        if (solution.student.toString() !== studentId) {
          logger.warn(`Student ${studentId} attempted to update solution ${solutionId} they don't own`);
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

        // Filter updates to only allowed fields
        for (const field of allowedFields) {
          if (field in updateData && updateData[field as keyof typeof updateData] !== undefined) {
            updates[field] = updateData[field as keyof typeof updateData];
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
          `Student ${studentId} successfully updated solution ${solutionId}`,
          {
            studentId,
            solutionId,
            updatedFields: Object.keys(updates)
          }
        );

        // Return the updated solution (populated within transaction)
        const populatedSolution = await Solution.findById(solutionId)
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

      if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(reviewData.status)) {
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
      if (reviewData.score !== undefined) {
        const score = Number(reviewData.score);
        if (isNaN(score) || score < 0 || score > 100) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Score must be between 0 and 100'
          );
        }
      }

      // Additional validation for specific status types
      if (reviewData.status === SolutionStatus.APPROVED && reviewData.score === undefined) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Score is required when approving a solution'
        );
      }

      return {
        status: reviewData.status as SolutionStatus.APPROVED | SolutionStatus.REJECTED,
        feedback: reviewData.feedback,
        score: reviewData.score
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
      // Validate IDs upfront to fail fast
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      logger.debug(`Architect ${architectId} attempting to claim solution ${solutionId} for review`);

      return await this.withTransaction(async (session) => {
        // Find the solution without populating challenge first
        const solution = await Solution.findById(solutionId).session(session);

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

        // Check if solution is already claimed by another architect
        if (solution.reviewedBy && solution.reviewedBy.toString() !== architectId) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            'This solution has already been claimed by another architect',
            true,
            'SOLUTION_ALREADY_CLAIMED'
          );
        }

        // Check if solution is already claimed by another architect
        if (solution.reviewedBy && solution.reviewedBy.toString() !== architectId) {
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

        // Apply the state transition
        solution.status = SolutionStatus.UNDER_REVIEW;
        solution.reviewedBy = new Types.ObjectId(architectId);
        solution.updatedAt = new Date();

        await solution.save({ session });

        logger.info(`Solution ${solutionId} claimed for review by architect ${architectId}`);

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
      // Validate IDs upfront to fail fast
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      logger.debug(`Architect ${architectId} attempting to review solution ${solutionId}`, {
        reviewStatus: reviewData.status
      });

      // Validate review data
      const validatedData = this.validateReviewData(reviewData);

      return await this.withTransaction(async (session) => {
        // Find the solution - OPTIMIZATION: Retrieve with a single query including references
        const solution = await Solution.findById(solutionId)
          .populate('challenge')
          .session(session);

        if (!solution) {
          throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
        }

        // Verify reviewer is the claiming architect
        if (!solution.reviewedBy || solution.reviewedBy.toString() !== architectId) {
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
              _id: challengeId,
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

        // Apply the state change
        solution.status = validatedData.status;
        solution.feedback = validatedData.feedback;
        if (validatedData.score !== undefined) solution.score = validatedData.score;
        solution.reviewedAt = new Date();

        await solution.save({ session });

        logger.info(
          `Solution ${solutionId} ${validatedData.status === SolutionStatus.APPROVED ? 'approved' : 'rejected'} ` +
          `by architect ${architectId}`
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
   * @returns The updated solution
   */
  async selectSolutionAsWinner(
    solutionId: string,
    companyId: string
  ): Promise<ISolution> {
    try {
      // Validate IDs upfront to fail fast
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid company ID format');
      }

      logger.debug(`Company ${companyId} attempting to select solution ${solutionId} as winner`);

      return await this.withTransaction(async (session) => {
        // Find the solution
        const solution = await Solution.findById(solutionId)
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

        if (challengeCompanyId !== companyId) {
          logger.warn(`Company ${companyId} attempted to select a solution for challenge owned by ${challengeCompanyId}`);
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

        // Apply the status change
        solution.status = SolutionStatus.SELECTED;
        solution.selectedAt = new Date();
        solution.selectedBy = new Types.ObjectId(companyId);

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
            challengeId,
            {
              $set: {
                status: ChallengeStatus.COMPLETED,
                completedAt: new Date()
              }
            },
            { session, new: true }
          );
        }

        logger.info(`Solution ${solutionId} selected as winner by company ${companyId}`);

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
      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      logger.debug(`Retrieving reviews for architect ${architectId}`, { options });

      const { status, page = 1, limit = 10 } = options;
      const skip = (Number(page) - 1) * Number(limit);

      // Build match criteria with proper typing
      const matchCriteria: Record<string, any> = {
        reviewedBy: new Types.ObjectId(architectId)
      };

      if (status) {
        matchCriteria.status = status;
      }

      // Define pipeline stages with more explicit typing
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

      const results = await Solution.aggregate(pipeline);

      const total = results[0]?.totalCount[0]?.count || 0;
      const data = results[0]?.paginatedResults || [];

      logger.debug(`Retrieved ${data.length} reviews for architect ${architectId}`, {
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
}

export const solutionService = new SolutionService();