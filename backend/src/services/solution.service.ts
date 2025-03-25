import mongoose, { Types } from 'mongoose';
import Solution from '../models/Solution';
import Challenge from '../models/Challenge';
import StudentProfile from '../models/StudentProfile';
import ArchitectProfile from '../models/ArchitectProfile';
import CompanyProfile from '../models/CompanyProfile';
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
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';
import { isValidTransition, transitionSolutionState } from '../utils/solution-state-manager';
import { executePaginatedQuery, PaginationOptions, PaginationResult } from '../utils/paginationUtils';

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
export class SolutionService {
  /**
   * Get a student profile ID from user ID
   * @param userId - User ID
   * @returns Student profile ID
   * @throws ApiError if profile not found
   */
  async getStudentProfileId(userId: string): Promise<string> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const studentProfile = await StudentProfile.findOne({ user: userId });

      if (!studentProfile) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
      }

      return studentProfile._id?.toString() || '';
    } catch (error) {
      logger.error(`Error getting student profile ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve student profile');
    }
  }

  /**
   * Get an architect profile ID from user ID
   * @param userId - User ID
   * @returns Architect profile ID
   * @throws ApiError if profile not found
   */
  async getArchitectProfileId(userId: string): Promise<string> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const architectProfile = await ArchitectProfile.findOne({ user: userId });

      if (!architectProfile) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Architect profile not found');
      }

      return architectProfile._id?.toString() || '';
    } catch (error) {
      logger.error(`Error getting architect profile ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve architect profile');
    }
  }

  /**
   * Get a company profile ID from user ID
   * @param userId - User ID
   * @returns Company profile ID
   * @throws ApiError if profile not found
   */
  async getCompanyProfileId(userId: string): Promise<string> {
    try {
      if (!userId) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User ID is required');
      }

      const companyProfile = await CompanyProfile.findOne({ user: userId });

      if (!companyProfile) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
      }

      return companyProfile._id?.toString() || ' ';
    } catch (error) {
      logger.error(`Error getting company profile ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve company profile');
    }
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
    solutionData: SolutionSubmissionData
  ): Promise<ISolution> {
    // Start a MongoDB session for transaction support
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
      }

      if (!Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID format');
      }

      // Validate required solution fields
      if (!solutionData.title || !solutionData.description || !solutionData.submissionUrl) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Solution title, description, and submission URL are required'
        );
      }

      // Check if the student exists
      const studentProfile = await StudentProfile.findById(studentId).session(session);
      if (!studentProfile) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
      }

      // Safely cast to IStudentProfile to ensure type safety
      const typedStudentProfile = studentProfile.toObject() as IStudentProfile;

      // Check if the challenge exists and is published
      const challenge = await Challenge.findById(challengeId).session(session);
      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Check if challenge is active
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot submit solution to a challenge with status: ${challenge.status}. Only active challenges accept submissions.`
        );
      }

      // Check if deadline has passed
      if (challenge.isDeadlinePassed()) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Challenge deadline has passed, no new submissions are allowed'
        );
      }

      // CRITICAL SECURITY CHECK: Verify student institution access for private challenges
      // This is a defense-in-depth security measure in addition to the route middleware
      if (challenge.visibility === ChallengeVisibility.PRIVATE) {
        // Make sure the challenge has allowedInstitutions configured
        if (!challenge.allowedInstitutions || challenge.allowedInstitutions.length === 0) {
          logger.warn(
            `Private challenge ${challengeId} has no allowed institutions configured`
          );

          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'This private challenge does not have any allowed institutions configured'
          );
        }

        // Make sure student has a university in their profile
        const studentUniversity = typedStudentProfile.university;

        if (!studentUniversity) {
          logger.warn(
            `Student ${studentProfile._id} attempted to access private challenge without university in profile`
          );

          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You must set your university in your profile to participate in private challenges'
          );
        }

        // Check if student's university is in the allowed list
        if (!challenge.allowedInstitutions.includes(studentUniversity)) {
          logger.warn(
            `Institution access denied: Student ${typedStudentProfile._id} from ${studentUniversity} ` +
            `attempted to submit to challenge ${challengeId} restricted to [${challenge.allowedInstitutions.join(', ')}]`,
            {
              studentId: typedStudentProfile._id,
              challengeId,
              studentUniversity,
              allowedInstitutions: challenge.allowedInstitutions
            }
          );

          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'Your institution does not have access to this private challenge'
          );
        }

        logger.info(
          `Institution access granted: Student from ${studentUniversity} ` +
          `allowed to submit to private challenge ${challengeId}`,
          {
            studentId: typedStudentProfile._id,
            challengeId,
            studentUniversity
          }
        );
      }

      // Check if the student has already submitted a solution
      const existingSolution = await Solution.findOne({
        challenge: challengeId,
        student: studentId
      }).session(session);

      if (existingSolution) {
        throw new ApiError(
          HTTP_STATUS.CONFLICT,
          'You have already submitted a solution to this challenge'
        );
      }

      // Check if the challenge has reached maximum participants
      if (challenge.maxParticipants && challenge.currentParticipants >= challenge.maxParticipants) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `This challenge has reached its maximum number of participants (${challenge.maxParticipants})`
        );
      }

      // Create the solution with explicit Schema type safety
      const solution = new Solution({
        title: solutionData.title,
        description: solutionData.description,
        submissionUrl: solutionData.submissionUrl,
        tags: solutionData.tags || [],
        challenge: new Types.ObjectId(challengeId),
        student: new Types.ObjectId(studentId),
        status: SolutionStatus.SUBMITTED
      });

      // Save the solution with session for transaction support
      await solution.save({ session });

      // Increment the current participants count atomically with transaction support
      const updatedChallenge = await Challenge.findByIdAndUpdate(
        challengeId,
        { $inc: { currentParticipants: 1 } },
        { session, new: true }
      );

      if (!updatedChallenge) {
        // This should never happen since we already verified the challenge exists
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to update challenge participant count'
        );
      }

      // Commit the transaction
      await session.commitTransaction();

      logger.info(
        `Student ${studentId} successfully submitted solution ${solution._id} for challenge ${challengeId}`,
        {
          studentId,
          challengeId,
          solutionId: solution._id
        }
      );

      // Populate after transaction is complete
      const populatedSolution = await Solution.findById(solution._id)
        .populate('challenge')
        .populate('student');

      if (!populatedSolution) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to retrieve solution after submission'
        );
      }

      return populatedSolution;

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      logger.error(
        `Error submitting solution: ${error instanceof Error ? error.message : String(error)}`,
        { studentId, challengeId, error }
      );

      // Re-throw ApiError instances as-is
      if (error instanceof ApiError) throw error;

      // For any other errors, wrap in a generic ApiError
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to submit solution due to an unexpected error'
      );
    } finally {
      // Always end the session
      session.endSession();
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

      const { status, page = 1, limit = 10, sortBy = 'updatedAt', sortOrder = 'desc' } = filters;

      const query: any = { student: studentId };

      if (status) {
        query.status = status;
      }

      const skip = (page - 1) * limit;

      // Create sort object for MongoDB
      const sort: Record<string, 1 | -1> = {};
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

      const [solutions, total] = await Promise.all([
        Solution.find(query)
          .populate('challenge', 'title description difficulty status deadline')
          .populate('reviewedBy', 'firstName lastName specialization')
          .populate('selectedBy', 'firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(limit),
        Solution.countDocuments(query)
      ]);

      logger.debug(`Retrieved ${solutions.length} solutions for student ${studentId}`);

      return {
        solutions,
        total,
        page,
        limit
      };
    } catch (error) {
      logger.error(
        `Error retrieving student solutions: ${error instanceof Error ? error.message : String(error)}`,
        { studentId, filters: JSON.stringify(filters), error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve student solutions'
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

      // Check if challenge exists
      const challenge = await Challenge.findById(challengeId);

      if (!challenge) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found');
      }

      // Role-based Authorization logic
      if (userRole === UserRole.COMPANY) {
        // Companies can only view their own challenges
        const companyId = await this.getCompanyProfileId(userId);

        if (challenge.company.toString() !== companyId) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'You do not have permission to view solutions for this challenge'
          );
        }
      } else if (userRole === UserRole.ARCHITECT) {
        // Architects can only view solutions for closed challenges
        if (challenge.status !== ChallengeStatus.CLOSED) {
          throw new ApiError(
            HTTP_STATUS.FORBIDDEN,
            'Only solutions for closed challenges can be viewed by architects'
          );
        }
      }

      // Build query based on filters
      const {
        status,
        search,
        score,
        page = 1,
        limit = 10,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = filters;

      const query: Record<string, any> = { challenge: challengeId };

      if (status) {
        query.status = status;
      }

      if (search) {
        query.$or = [
          { title: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }

      if (score) {
        query.score = {};
        if (score.min !== undefined) query.score.$gte = score.min;
        if (score.max !== undefined) query.score.$lte = score.max;
      }

      const skip = (page - 1) * limit;

      // Create sort object
      const sort: Record<string, 1 | -1> = {};
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Get solutions with pagination
      const [solutions, total] = await Promise.all([
        Solution.find(query)
          .populate('student', 'firstName lastName university')
          .populate('reviewedBy', 'firstName lastName')
          .populate('selectedBy', 'firstName lastName')
          .sort(sort)
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
    } catch (error) {
      logger.error(
        `Error getting challenge solutions: ${error instanceof Error ? error.message : String(error)}`,
        { challengeId, userId, userRole, filters: JSON.stringify(filters), error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve challenge solutions'
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
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

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
          const studentId = await this.getStudentProfileId(userId);

          // Handle both populated and non-populated student
          const solutionStudentId = solution.student instanceof mongoose.Types.ObjectId || typeof solution.student === 'string'
            ? solution.student.toString()
            : (solution.student as any)?._id?.toString();

          if (!solutionStudentId || solutionStudentId !== studentId) {
            logger.warn(`Student ${studentId} attempted to access solution ${solutionId} they do not own`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view this solution'
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
          const companyProfileId = await this.getCompanyProfileId(userId);

          if (companyId !== companyProfileId) {
            logger.warn(`Company ${companyProfileId} attempted to access solution for challenge owned by ${companyId}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view this solution'
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

          if (typeof challenge === 'string' || challenge instanceof mongoose.Types.ObjectId) {
            // If challenge is just an ID, we need to fetch it
            const fullChallenge = await Challenge.findById(challenge);
            challengeStatus = fullChallenge?.status;
          } else {
            // If challenge is populated, extract status
            challengeStatus = (challenge as any).status;
          }

          if (challengeStatus !== ChallengeStatus.CLOSED) {
            logger.warn(`Architect attempted to access solution for challenge with status ${challengeStatus}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'Architects can only view solutions for closed challenges'
            );
          }
          break;
        }

        case 'admin':
          // Admins can view all solutions
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
        'Failed to retrieve solution due to an unexpected error'
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
    }
  ): Promise<ISolution> {
    // Start a MongoDB session for transaction support
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student ID format');
      }

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

      const allowedFields = ['title', 'description', 'submissionUrl'];
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

      // Update the solution with transaction support
      solution.set(updates);
      await solution.save({ session });

      await session.commitTransaction();

      logger.info(
        `Student ${studentId} successfully updated solution ${solutionId}`,
        {
          studentId,
          solutionId,
          updatedFields: Object.keys(updates)
        }
      );

      // Return the updated solution (populated after transaction is complete)
      const populatedSolution = await Solution.findById(solutionId)
        .populate('challenge')
        .populate('student');

      if (!populatedSolution) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to retrieve solution after updating'
        );
      }

      return populatedSolution;

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      logger.error(
        `Error updating solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, studentId, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to update solution due to an unexpected error'
      );
    } finally {
      // Always end the session
      session.endSession();
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
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      // Find the solution
      const solution = await Solution.findById(solutionId)
        .populate('challenge')
        .session(session);

      if (!solution) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Solution not found');
      }

      // Check if the challenge is closed (only closed challenges can be reviewed)
      if (solution.challenge && typeof solution.challenge !== 'string') {
        if (typeof solution.challenge !== 'string' && !(solution.challenge instanceof mongoose.Types.ObjectId) && solution.challenge.status !== ChallengeStatus.CLOSED) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Solutions can only be claimed for challenges with status 'closed'. ` +
            `Current challenge status: ${solution.challenge.status}.`
          );
        }
      }

      // Use the state transition manager to validate and apply the transition
      // Instead of directly setting the status
      if (!isValidTransition(solution.status as SolutionStatus, SolutionStatus.UNDER_REVIEW)) {
        throw new ApiError(
          HTTP_STATUS.CONFLICT,
          `Invalid state transition from ${solution.status} to ${SolutionStatus.UNDER_REVIEW}. Only 'submitted' solutions can be claimed.`
        );
      }

      // Apply the state transition
      transitionSolutionState(solution, SolutionStatus.UNDER_REVIEW, architectId);
      solution.reviewedBy = new Types.ObjectId(architectId);

      await solution.save({ session });

      // Rest of the method remains the same
      await session.commitTransaction();

      logger.info(`Solution ${solutionId} claimed for review by architect ${architectId}`);

      // Populate after transaction is complete
      const populatedSolution = await Solution.findById(solution._id)
        .populate('challenge')
        .populate('student')
        .populate('reviewedBy');

      if (!populatedSolution) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to retrieve solution after updating'
        );
      }

      return populatedSolution;

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      logger.error(
        `Error claiming solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, architectId, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to claim solution for review'
      );
    } finally {
      // End session
      session.endSession();
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
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid architect ID format');
      }

      // Validate review data
      const validatedData = this.validateReviewData(reviewData);

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

      // Use state transition manager to validate transition
      if (!isValidTransition(solution.status as SolutionStatus, validatedData.status)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid state transition from ${solution.status} to ${validatedData.status}. Only solutions in 'under_review' status can be reviewed.`
        );
      }

      // For approvals, check if challenge has reached approval limit
      if (validatedData.status === SolutionStatus.APPROVED && solution.challenge) {
        // ...existing approval limit check code...
      }

      // Apply the state transition instead of directly setting status
      transitionSolutionState(solution, validatedData.status, architectId);
      solution.feedback = validatedData.feedback;
      if (validatedData.score !== undefined) solution.score = validatedData.score;
      solution.reviewedAt = new Date();

      await solution.save({ session });

      await session.commitTransaction();

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
        ]);

      if (!populatedSolution) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to retrieve solution after updating'
        );
      }

      return populatedSolution;

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      logger.error(
        `Error reviewing solution: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, architectId, reviewData: JSON.stringify(reviewData), error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to review solution'
      );
    } finally {
      // End session
      session.endSession();
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
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(solutionId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution ID format');
      }

      if (!Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid company ID format');
      }

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

      // Use state transition manager to validate transition to SELECTED
      if (!isValidTransition(solution.status as SolutionStatus, SolutionStatus.SELECTED)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid state transition from ${solution.status} to ${SolutionStatus.SELECTED}. Only approved solutions can be selected as winners.`
        );
      }

      // Apply the state transition
      transitionSolutionState(solution, SolutionStatus.SELECTED, companyId);
      solution.selectedAt = new Date();
      solution.selectedBy = solution.reviewedBy; // Typically the same architect who approved it

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

      // Commit the transaction
      await session.commitTransaction();

      logger.info(`Solution ${solutionId} selected as winner by company ${companyId}`);

      // Populate after transaction is complete
      const populatedSolution = await Solution.findById(solution._id)
        .populate('challenge')
        .populate('student')
        .populate('reviewedBy')
        .populate('selectedBy');

      if (!populatedSolution) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Failed to retrieve solution after selection'
        );
      }

      return populatedSolution;

    } catch (error) {
      // Abort transaction on error
      await session.abortTransaction();

      logger.error(
        `Error selecting solution as winner: ${error instanceof Error ? error.message : String(error)}`,
        { solutionId, companyId, error }
      );

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to select solution as winner'
      );
    } finally {
      // End session
      session.endSession();
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
        { architectId, error }
      );
    
      if (error instanceof ApiError) throw error;
    
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve architect reviews'
      );
    }
  }
}
export const solutionService = new SolutionService();