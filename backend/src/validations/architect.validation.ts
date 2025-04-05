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

export const createArchitectSchema = z.object({
  // User credentials
  email: z.string().email('Please provide a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  
  // Basic profile information
  firstName: z.string().min(2, 'First name must be at least 2 characters').max(50),
  lastName: z.string().min(2, 'Last name must be at least 2 characters').max(50),
  specialization: z.string().optional(),
  yearsOfExperience: z.number().int().min(0).optional(),
  
  // Optional fields
  bio: z.string().max(500, 'Bio cannot exceed 500 characters').optional(),
  skills: z.array(z.string()).optional(),
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