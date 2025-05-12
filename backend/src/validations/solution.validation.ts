import { z } from 'zod';
import { SolutionStatus } from '../models/interfaces';

/**
 * Zod schema for submitting a solution
 */
export const submitSolutionSchema = z.object({
  challengeId: z.string({
    required_error: 'Challenge ID is required'
  }).min(1, 'Challenge ID is required'),
  
  challenge: z.string({
    invalid_type_error: 'Challenge ID must be a string'
  }).min(1, 'Challenge ID is required').optional(),
  
  title: z.string({
    required_error: 'Title is required'
  }).max(100, 'Title cannot exceed 100 characters').trim(),
  
  description: z.string({
    required_error: 'Description is required'
  }).min(1, 'Description is required').trim(),
  
  submissionUrl: z.string({
    required_error: 'Submission URL is required'
  }).url('Submission URL must be a valid URL').trim(),
});

/**
 * Zod schema for updating a solution
 */
export const updateSolutionSchema = z.object({
  title: z.string({
    required_error: 'Title is required'
  }).max(100, 'Title cannot exceed 100 characters').trim(),
  
  description: z.string({
    required_error: 'Description is required'
  }).min(1, 'Description is required').trim(),
  
  submissionUrl: z.string({
    required_error: 'Submission URL is required'
  }).url('Submission URL must be a valid URL').trim(),
});

/**
 * Zod schema for reviewing a solution
 */
export const reviewSolutionSchema = z.object({
  status: z.enum([SolutionStatus.APPROVED, SolutionStatus.REJECTED], {
    required_error: 'Status is required',
    invalid_type_error: 'Status must be either approved or rejected'
  }),
  
  feedback: z.string({
    invalid_type_error: 'Feedback must be a string'
  }).trim(),
  
  score: z.number({
    invalid_type_error: 'Score must be a number'
  }).min(0, 'Score cannot be negative').max(100, 'Score cannot exceed 100').optional(),
}).superRefine((data, ctx) => {
  // If status is rejected, feedback is required
  if (data.status === SolutionStatus.REJECTED && (!data.feedback || data.feedback.trim().length === 0)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Feedback is required for rejected solutions',
      path: ['feedback']
    });
  }
  
  // If status is approved, score is required
  if (data.status === SolutionStatus.APPROVED && (data.score === undefined || data.score === null)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Score is required for approved solutions',
      path: ['score']
    });
  }
});

/**
 * Zod schema for company selection of winning solution
 */
export const selectSolutionAsWinnerSchema = z.object({
  companyFeedback: z.string()
    .max(2000, 'Feedback cannot exceed 2000 characters')
    .optional(),
  
  selectionReason: z.string()
    .max(1000, 'Selection reason cannot exceed 1000 characters')
    .optional()
});

// Type inference from zod schemas
export type SubmitSolutionInput = z.infer<typeof submitSolutionSchema>;
export type UpdateSolutionInput = z.infer<typeof updateSolutionSchema>;
export type ReviewSolutionInput = z.infer<typeof reviewSolutionSchema>;

/**
 * @deprecated Use validateRequest middleware instead
 * These functions are kept for backward compatibility
 */
import { Request, Response, NextFunction } from 'express';
import { HTTP_STATUS } from '../constants';

export const validateSubmitSolution = (req: Request, res: Response, next: NextFunction): void => {
  const result = submitSolutionSchema.safeParse(req.body);
  
  if (!result.success) {
    const errorMessages = result.error.errors.map(error => error.message);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errors: errorMessages
    });
    return;
  }
  
  next();
};

export const validateUpdateSolution = (req: Request, res: Response, next: NextFunction): void => {
  const result = updateSolutionSchema.safeParse(req.body);
  
  if (!result.success) {
    const errorMessages = result.error.errors.map(error => error.message);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errors: errorMessages
    });
    return;
  }
  
  next();
};

export const validateReviewSolution = (req: Request, res: Response, next: NextFunction): void => {
  const result = reviewSolutionSchema.safeParse(req.body);
  
  if (!result.success) {
    const errorMessages = result.error.errors.map(error => error.message);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errors: errorMessages
    });
    return;
  }
  
  next();
};