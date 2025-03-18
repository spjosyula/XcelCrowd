import { z } from 'zod';
import { SolutionStatus } from '../models/interfaces';

/**
 * Validation schema for creating/updating architect profile
 */
export const architectProfileSchema = z.object({
  firstName: z.string().min(1, 'First name is required').max(50, 'First name is too long').optional(),
  lastName: z.string().min(1, 'Last name is required').max(50, 'Last name is too long').optional(),
  specialization: z.string().max(100, 'Specialization is too long').optional(),
  yearsOfExperience: z.number().min(0, 'Years of experience cannot be negative').optional(),
  bio: z.string().max(500, 'Bio cannot exceed 500 characters').optional(),
  profilePicture: z.string().url('Invalid URL format').optional(),
  skills: z.array(z.string()).optional(),
  certifications: z.array(z.string()).optional()
});

/**
 * Validation schema for reviewing a solution
 */
export const reviewSolutionSchema = z.object({
  status: z.enum([SolutionStatus.APPROVED, SolutionStatus.REJECTED], {
    errorMap: () => ({ message: 'Status must be either approved or rejected' })
  }),
  feedback: z.string().min(10, 'Feedback must be at least 10 characters').max(1000, 'Feedback cannot exceed 1000 characters'),
  score: z.number().min(0, 'Score cannot be negative').max(100, 'Score cannot exceed 100').optional()
});

/**
 * Validation schema for filtering solutions
 */
export const filterSolutionsSchema = z.object({
  status: z.enum([
    SolutionStatus.SUBMITTED, 
    SolutionStatus.UNDER_REVIEW, 
    SolutionStatus.REJECTED, 
    SolutionStatus.APPROVED, 
    SolutionStatus.SELECTED
  ]).optional(),
  challengeId: z.string().optional(),
  studentId: z.string().optional(),
  page: z.number().int().positive().optional().default(1),
  limit: z.number().int().positive().max(100).optional().default(10)
}); 