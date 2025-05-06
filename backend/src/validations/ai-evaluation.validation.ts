import { z } from 'zod';
import { Types } from 'mongoose';

/**
 * Priority levels for evaluation processing
 */
export enum EvaluationPriority {
  HIGH = 'high',
  NORMAL = 'normal',
  LOW = 'low'
}

/**
 * MongoDB ObjectId validation schema
 */
const objectIdValidator = (errorMessage: string = 'Invalid ObjectId format') => 
  z.string().refine(val => Types.ObjectId.isValid(val), {
    message: errorMessage
  });

/**
 * Validation schema for starting an AI evaluation
 */
export const startEvaluationSchema = z.object({
  params: z.object({
    solutionId: objectIdValidator('Invalid solution ID format')
  }),
  body: z.object({
    priority: z.enum([EvaluationPriority.HIGH, EvaluationPriority.NORMAL, EvaluationPriority.LOW], {
      errorMap: () => ({ message: 'Priority must be high, normal, or low' })
    }).optional().default(EvaluationPriority.NORMAL),
    
    notifyOnCompletion: z.boolean().optional().default(false),
    
    evaluationMode: z.enum(['standard', 'detailed', 'quick'], {
      errorMap: () => ({ message: 'Evaluation mode must be standard, detailed, or quick' })
    }).optional().default('standard'),
    
    tags: z.array(z.string().trim().min(1).max(20))
      .max(5, 'Maximum 5 tags allowed')
      .optional(),
      
    skipSteps: z.array(z.enum(['spam', 'requirements', 'code', 'scoring']))
      .max(2, 'Cannot skip more than 2 steps')
      .optional()
  }).optional().default({})
}).superRefine((data, ctx) => {
  // Custom validation logic
  if (data.body?.priority === EvaluationPriority.HIGH && data.body?.evaluationMode === 'quick') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'High priority evaluations cannot use quick mode',
      path: ['body.evaluationMode']
    });
  }
  
  // Prevent skipping critical steps with detailed mode
  if (data.body?.evaluationMode === 'detailed' && 
      data.body?.skipSteps && 
      data.body.skipSteps.length > 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Cannot skip steps in detailed evaluation mode',
      path: ['body.skipSteps']
    });
  }
});

/**
 * Validation schema for getting evaluation status
 */
export const getStatusSchema = z.object({
  params: z.object({
    solutionId: objectIdValidator('Invalid solution ID format')
  }),
  query: z.object({
    includeDetails: z.preprocess(
      // Convert any input value to proper boolean
      (val) => val === 'true' || val === true,
      z.boolean().default(false)
    ),
    fields: z.preprocess(
      // Handle array of fields with proper defaults
      (val) => typeof val === 'string' 
        ? val.split(',').filter(field => field.trim().length > 0) 
        : [],
      z.array(z.string()).default([])
    )
  }).default({})
});

/**
 * Validation schema for retrying a failed evaluation
 */
export const retryEvaluationSchema = z.object({
  params: z.object({
    solutionId: objectIdValidator('Invalid solution ID format')
  }),
  body: z.object({
    forceRestart: z.boolean().optional().default(false),
    priority: z.enum([EvaluationPriority.HIGH, EvaluationPriority.NORMAL, EvaluationPriority.LOW])
      .optional().default(EvaluationPriority.NORMAL),
    skipSteps: z.array(z.enum(['spam', 'requirements', 'code', 'scoring']))
      .max(2, 'Cannot skip more than 2 steps')
      .optional()
  }).optional().default({})
});

/**
 * Validation schema for getting evaluation analytics
 */
export const evaluationAnalyticsSchema = z.object({
  query: z.object({
    startDate: z.string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format')
      .optional()
      .transform(val => val ? new Date(val) : undefined),
      
    endDate: z.string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format')
      .optional()
      .transform(val => val ? new Date(val) : undefined),
      
    challengeId: z.string()
      .optional()
      .refine(val => !val || Types.ObjectId.isValid(val), {
        message: 'Challenge ID must be a valid ObjectId'
      }),
      
    groupBy: z.enum(['day', 'week', 'month', 'challenge', 'status'])
      .optional()
      .default('day'),
      
    limit: z.string()
      .optional()
      .transform(val => val ? parseInt(val, 10) : 50)
      .refine(val => val > 0 && val <= 100, {
        message: 'Limit must be between 1 and 100'
      })
  }).optional().default({})
}).superRefine((data, ctx) => {
  // Validate date range if both dates are provided
  if (data.query?.startDate && data.query?.endDate) {
    const start = new Date(data.query.startDate);
    const end = new Date(data.query.endDate);
    
    if (end < start) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'End date cannot be before start date',
        path: ['query.endDate']
      });
    }
    
    // Prevent queries spanning more than 90 days for performance
    const daysDiff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDiff > 90) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Date range cannot exceed 90 days',
        path: ['query.startDate', 'query.endDate']
      });
    }
  }
});

// Type inference from zod schemas
export type StartEvaluationInput = z.infer<typeof startEvaluationSchema>;
export type GetStatusInput = z.infer<typeof getStatusSchema>;
export type RetryEvaluationInput = z.infer<typeof retryEvaluationSchema>;
export type EvaluationAnalyticsInput = z.infer<typeof evaluationAnalyticsSchema>;