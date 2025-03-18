import { Types } from 'mongoose';
import { Solution, Challenge } from '../models';
import { ISolution, SolutionStatus, ChallengeStatus } from '../models/interfaces';
import { ApiError } from '../utils/ApiError';

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
    // Check if the challenge exists and is published
    const challenge = await Challenge.findById(challengeId);
    
    if (!challenge) {
      throw ApiError.notFound('Challenge not found');
    }
    
    if (challenge.status !== ChallengeStatus.ACTIVE) {
      throw ApiError.badRequest('Cannot submit solution to a challenge that is not published');
    }
    
    // Check if deadline has passed
    if (challenge.isDeadlinePassed()) {
      throw ApiError.badRequest('Challenge deadline has passed, no new submissions are allowed');
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
    
    return solution.populate([
      { path: 'challenge' },
      { path: 'student' }
    ]);
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
    const solution = await Solution.findOne({
      _id: solutionId,
      student: studentId
    });
    
    if (!solution) {
      throw ApiError.notFound('Solution not found or you do not have permission to update it');
    }
    
    // Only allow updates if the solution is in submitted or rejected status
    if (solution.status !== SolutionStatus.SUBMITTED && solution.status !== SolutionStatus.REJECTED) {
      throw ApiError.badRequest('Cannot update a solution that is under review, approved, or selected');
    }
    
    // Update allowed fields
    if (updateData.title) solution.title = updateData.title;
    if (updateData.description) solution.description = updateData.description;
    if (updateData.submissionUrl) solution.submissionUrl = updateData.submissionUrl;
    
    // Reset status to submitted if it was rejected
    if (solution.status === SolutionStatus.REJECTED) {
      solution.status = SolutionStatus.SUBMITTED;
      solution.feedback = undefined;
      solution.reviewedBy = undefined;
      solution.reviewedAt = undefined;
      solution.score = undefined;
    }
    
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