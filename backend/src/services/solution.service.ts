import { Types } from 'mongoose';
import { Solution, Challenge, StudentProfile } from '../models';
import { ISolution, SolutionStatus, ChallengeStatus, ChallengeVisibility, HTTP_STATUS, IStudentProfile } from '../models/interfaces';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';
import mongoose from 'mongoose';

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
 */
export class SolutionService {
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
      if (!Types.ObjectId.isValid(studentId) || !Types.ObjectId.isValid(challengeId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid student or challenge ID format');
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
   * Get a solution by ID with enhanced security checks
   * @param solutionId - The ID of the solution
   * @param userId - The user ID requesting the solution (for authorization)
   * @param userRole - The role of the user (for role-based access control)
   * @returns The solution with all relevant populated fields
   * @throws ApiError if solution not found or user not authorized
   */
  async getSolutionById(
    solutionId: string,
    userId?: string,
    userRole?: string
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

      // Skip authorization checks if userId or userRole not provided
      if (!userId || !userRole) {
        logger.warn('getSolutionById called without userId or userRole. Skipping authorization checks.');
        return solution;
      }

      // Normalize role to lowercase for consistent comparison
      const role = userRole.toLowerCase();

      // Check permissions based on user role
      switch (role) {
        case 'student': {
          // Students can only view their own solutions
          const studentProfile = await StudentProfile.findOne({ user: userId });

          if (!studentProfile) {
            logger.warn(`Student profile not found for user ${userId}`);
            throw new ApiError(HTTP_STATUS.FORBIDDEN, 'Student profile not found');
          }

          // Handle both populated and non-populated student
          const studentId = solution.student instanceof mongoose.Types.ObjectId || typeof solution.student === 'string'
            ? solution.student.toString()
            : solution.student?._id?.toString();

          if (!studentId || studentId !== (studentProfile._id as mongoose.Types.ObjectId).toString()) {
            logger.warn(`Student ${studentProfile._id} attempted to access solution ${solutionId} they do not own`);
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
            companyId = challenge.company?._id?.toString() ||
              (typeof challenge.company === 'string' ? challenge.company : undefined);
          }

          if (!companyId) {
            throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Challenge has no associated company');
          }

          // Get company profile ID from user ID
          const companyProfileId = await this.getUserProfileId(userId);

          if (!companyProfileId) {
            throw new ApiError(HTTP_STATUS.FORBIDDEN, 'Company profile not found');
          }

          if (companyId !== companyProfileId) {
            logger.warn(`Company ${companyProfileId} attempted to access solution for challenge owned by company ${companyId}`);
            throw new ApiError(
              HTTP_STATUS.FORBIDDEN,
              'You do not have permission to view solutions for this challenge'
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
            challengeStatus = challenge.status;
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
   * Helper method to get a user's profile ID
   * @param userId - The user ID
   * @returns The profile ID or undefined if not found
   */
  private async getUserProfileId(userId: string): Promise<string | undefined> {
    try {
      // First check if it's a student
      const studentProfile = await StudentProfile.findOne({ user: userId });
      if (studentProfile && studentProfile._id) {
        return studentProfile._id.toString();
      }

      // Could check other profile types here if needed

      return undefined;
    } catch (error) {
      logger.error(`Error getting user profile: ${error instanceof Error ? error.message : String(error)}`);
      return undefined;
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
      if (!Types.ObjectId.isValid(solutionId) || !Types.ObjectId.isValid(studentId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution or student ID format');
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
   * Get solutions by student ID with enhanced filtering and pagination
   * @param studentId - The ID of the student
   * @param filters - Optional filters
   * @returns List of solutions
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
      if (!Types.ObjectId.isValid(solutionId) || !Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution or architect ID format');
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

      // Check if solution is already claimed or past review
      if (solution.status !== SolutionStatus.SUBMITTED) {
        throw new ApiError(
          HTTP_STATUS.CONFLICT,
          `Solution is already in status: ${solution.status}. Only 'submitted' solutions can be claimed.`
        );
      }

      // Update solution to under review status
      solution.status = SolutionStatus.UNDER_REVIEW;
      solution.reviewedBy = new Types.ObjectId(architectId);

      await solution.save({ session });

      // Commit the transaction
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
      status: SolutionStatus.APPROVED | SolutionStatus.REJECTED;
      feedback: string;
      score?: number;
    }
  ): Promise<ISolution> {
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Validate IDs
      if (!Types.ObjectId.isValid(solutionId) || !Types.ObjectId.isValid(architectId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution or architect ID format');
      }

      // Validate status
      if (![SolutionStatus.APPROVED, SolutionStatus.REJECTED].includes(reviewData.status)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Status must be either approved or rejected'
        );
      }

      // Validate feedback
      if (!reviewData.feedback) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Feedback is required');
      }

      // Validate score if provided
      if (reviewData.score !== undefined) {
        if (reviewData.score < 0 || reviewData.score > 100) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Score must be between 0 and 100'
          );
        }
      }

      // Find the solution
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

      // Verify solution is in UNDER_REVIEW status
      if (solution.status !== SolutionStatus.UNDER_REVIEW) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Cannot review a solution with status: ${solution.status}. Only solutions in 'under_review' status can be reviewed.`
        );
      }

      // For approvals, check if challenge has reached approval limit
      if (reviewData.status === SolutionStatus.APPROVED && solution.challenge) {
        // Handle both populated and non-populated challenge cases
        let hasReachedLimit = false;

        if (solution.challenge instanceof mongoose.Types.ObjectId || typeof solution.challenge === 'string') {
          // If challenge is just an ID, fetch the full challenge
          const fullChallenge = await Challenge.findById(solution.challenge).session(session);
          if (fullChallenge) {
            // Check if approval limit reached using the fetched challenge
            if (fullChallenge.maxApprovedSolutions &&
              fullChallenge.approvedSolutionsCount >= fullChallenge.maxApprovedSolutions) {
              hasReachedLimit = true;
            }
          }
        } else {
          // It's a populated IChallenge object - use type assertion with proper checks
          const challenge = solution.challenge as any;

          if (typeof challenge.isApprovalLimitReached === 'function') {
            hasReachedLimit = challenge.isApprovalLimitReached();
          } else if (typeof challenge.maxApprovedSolutions === 'number' &&
            typeof challenge.approvedSolutionsCount === 'number') {
            // Fallback to direct property checks if method isn't available
            if (challenge.maxApprovedSolutions &&
              challenge.approvedSolutionsCount >= challenge.maxApprovedSolutions) {
              hasReachedLimit = true;
            }
          }
        }

        if (hasReachedLimit) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Challenge has reached maximum number of approved solutions'
          );
        }

        // Increment approved solutions count for the challenge
        const challengeId = solution.challenge instanceof mongoose.Types.ObjectId || typeof solution.challenge === 'string'
          ? solution.challenge
          : solution.challenge._id;

        await Challenge.findByIdAndUpdate(
          challengeId,
          { $inc: { approvedSolutionsCount: 1 } },
          { session, new: true }
        );
      }

      // Update solution with review data
      solution.status = reviewData.status;
      solution.feedback = reviewData.feedback;
      if (reviewData.score !== undefined) solution.score = reviewData.score;
      solution.reviewedAt = new Date();

      await solution.save({ session });

      // Commit the transaction
      await session.commitTransaction();

      logger.info(
        `Solution ${solutionId} ${reviewData.status === SolutionStatus.APPROVED ? 'approved' : 'rejected'} ` +
        `by architect ${architectId}`
      );

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
      if (!Types.ObjectId.isValid(solutionId) || !Types.ObjectId.isValid(companyId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid solution or company ID format');
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

      // Verify solution is in APPROVED status
      if (solution.status !== SolutionStatus.APPROVED) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Only approved solutions can be selected as winners'
        );
      }

      // Update solution to selected status
      solution.status = SolutionStatus.SELECTED;
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
} 