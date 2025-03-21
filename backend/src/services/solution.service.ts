import { Types } from 'mongoose';
import { Solution, Challenge, StudentProfile } from '../models';
import { ISolution, SolutionStatus, ChallengeStatus, ChallengeVisibility } from '../models/interfaces';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';

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
   */
  async submitSolution(
    studentId: string,
    challengeId: string,
    solutionData: Partial<ISolution>
  ): Promise<ISolution> {
    try {
      // Check if the challenge exists and is published
      const challenge = await Challenge.findById(challengeId);
      
      if (!challenge) {
        throw ApiError.notFound('Challenge not found');
      }
      
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        throw ApiError.badRequest('Cannot submit solution to a challenge that is not active');
      }
      
      // Check if deadline has passed
      if (challenge.isDeadlinePassed()) {
        throw ApiError.badRequest('Challenge deadline has passed, no new submissions are allowed');
      }

      // Verify student institution access for private challenges
      if (challenge.visibility === ChallengeVisibility.PRIVATE && challenge.allowedInstitutions?.length) {
        const studentProfile = await StudentProfile.findById(studentId);
        
        if (!studentProfile) {
          throw ApiError.badRequest('Student profile not found');
        }
        
        const studentUniversity = studentProfile.university;
        
        if (!studentUniversity || !challenge.allowedInstitutions.includes(studentUniversity)) {
          throw ApiError.forbidden('You do not have permission to submit a solution to this challenge');
        }
      }
      
      // Check if the student has already submitted a solution
      const existingSolution = await Solution.findOne({
        challenge: challengeId,
        student: studentId
      });
      
      if (existingSolution) {
        throw ApiError.conflict('You have already submitted a solution to this challenge');
      }
      
      // Check if the challenge has reached maximum participants
      if (challenge.maxParticipants && challenge.currentParticipants >= challenge.maxParticipants) {
        throw ApiError.badRequest('This challenge has reached its maximum number of participants');
      }
      
      // Create the solution
      const solution = new Solution({
        ...solutionData,
        challenge: challengeId,
        student: studentId,
        status: SolutionStatus.SUBMITTED
      });
      
      await solution.save();
      
      // Increment the current participants count
      challenge.currentParticipants += 1;
      await challenge.save();
      
      logger.info(`Student ${studentId} submitted solution for challenge ${challengeId}`);
      
      return solution.populate([
        { path: 'challenge' },
        { path: 'student' }
      ]);
    } catch (error) {
      logger.error(`Error submitting solution: ${error instanceof Error ? error.message : String(error)}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(500, 'Failed to submit solution');
    }
  }

  /**
   * Get a solution by ID
   * @param solutionId - The ID of the solution
   * @param studentId - The ID of the student (optional, for authorization)
   * @returns The solution
   */
  async getSolutionById(solutionId: string, studentId?: string): Promise<ISolution> {
    const solution = await Solution.findById(solutionId)
      .populate('challenge')
      .populate('student')
      .populate('reviewedBy');
    
    if (!solution) {
      throw ApiError.notFound('Solution not found');
    }
    
    // If studentId is provided, check if the solution belongs to the student
    if (studentId && solution.student && (solution.student as any)._id.toString() !== studentId) {
      throw ApiError.forbidden('You do not have permission to view this solution');
    }
    
    return solution;
  }

  /**
   * Update a solution
   * @param solutionId - The ID of the solution
   * @param studentId - The ID of the student
   * @param updateData - The update data
   * @returns The updated solution
   */
  async updateSolution(
    solutionId: string,
    studentId: string,
    updateData: Partial<ISolution>
  ): Promise<ISolution> {
    // Find the solution with student verification
    const solution = await Solution.findOne({
      _id: solutionId,
      student: studentId
    }).populate('challenge');
    
    if (!solution) {
      throw ApiError.notFound('Solution not found or you do not have permission to update it');
    }
    
    // Check if the challenge deadline has passed
    if (solution.challenge && (solution.challenge as any).isDeadlinePassed()) {
      throw ApiError.badRequest('Challenge deadline has passed, no updates are allowed');
    }
    
    // Only allow updates if the solution is in submitted or rejected status
    if (solution.status !== SolutionStatus.SUBMITTED && solution.status !== SolutionStatus.REJECTED) {
      throw ApiError.badRequest('Cannot update a solution that is under review, approved, or selected');
    }
    
    // Update only allowed fields using object assignment
    const allowedUpdates = {
      title: updateData.title,
      description: updateData.description,
      submissionUrl: updateData.submissionUrl
    };
    
    // Only assign defined values
    (Object.keys(allowedUpdates) as Array<keyof typeof allowedUpdates>).forEach(key => {
      if (allowedUpdates[key] !== undefined) {
        solution[key] = allowedUpdates[key];
      }
    });
    
    // Track the update
    solution.updatedAt = new Date();
    
    await solution.save();
    
    return solution.populate([
      { path: 'challenge' },
      { path: 'student' }
    ]);
  }

  /**
   * Get solutions by student ID
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
    }
  ): Promise<{ solutions: ISolution[]; total: number; page: number; limit: number }> {
    const { status, page = 1, limit = 10 } = filters;
    
    const query: any = { student: studentId };
    
    if (status) {
      query.status = status;
    }
    
    const skip = (page - 1) * limit;
    
    const [solutions, total] = await Promise.all([
      Solution.find(query)
        .populate('challenge', 'title description difficulty')
        .populate('reviewedBy', 'firstName lastName specialization')
        .sort({ updatedAt: -1 })
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
  }
} 