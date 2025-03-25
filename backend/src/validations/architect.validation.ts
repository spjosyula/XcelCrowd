import { z } from 'zod';
import { SolutionStatus } from '../models/interfaces';
import { Types } from 'mongoose';

// Validation schema for architect profile updates
export const architectProfileSchema = z.object({
  firstName: z.string().min(2).max(50),
  lastName: z.string().min(2).max(50),
  bio: z.string().optional(),
  skills: z.array(z.string()).optional(),
  company: z.string().optional(),
  jobTitle: z.string().optional(),
  yearsOfExperience: z.number().int().min(0).optional(),
  linkedInProfile: z.string().url().optional(),
  githubProfile: z.string().url().optional(),
  specializations: z.array(z.string()).optional(),
  certifications: z.array(z.string()).optional()
});

// Validation schema for solution review submission
export const reviewSolutionSchema = z.object({
  status: z.enum([SolutionStatus.APPROVED, SolutionStatus.REJECTED]),
  feedback: z.string().min(10).max(5000),
  score: z.number().min(0).max(100).optional()
});

// Validation schema for filtering solutions
export const filterSolutionsSchema = z.object({
  status: z.enum([
    SolutionStatus.DRAFT,
    SolutionStatus.SUBMITTED,
    SolutionStatus.UNDER_REVIEW,
    SolutionStatus.APPROVED,
    SolutionStatus.REJECTED,
    SolutionStatus.SELECTED
  ]).optional(),
  challengeId: z.string().optional()
    .refine(val => !val || Types.ObjectId.isValid(val), {
      message: 'Challenge ID must be a valid ObjectId'
    }),
  studentId: z.string().optional()
    .refine(val => !val || Types.ObjectId.isValid(val), {
      message: 'Student ID must be a valid ObjectId'
    }),
  page: z.number().int().positive().optional(),
  limit: z.number().int().positive().max(100).optional()
});

// Validation schema for selecting solutions for the company
export const selectSolutionsSchema = z.object({
  solutionIds: z.array(z.string())
    .min(1, "At least one solution ID must be provided")
    .refine(ids => ids.every(id => Types.ObjectId.isValid(id)), {
      message: "All solution IDs must be valid ObjectIds"
    })
});