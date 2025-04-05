import { z } from 'zod';
import { ChallengeStatus, ChallengeDifficulty, ChallengeVisibility } from '../models/interfaces';

/**
 * Zod schema for creating a challenge
 */
export const createChallengeSchema = z.object({
  title: z.string()
    .min(1, 'Title is required')
    .max(100, 'Title cannot exceed 100 characters')
    .trim(),

  description: z.string()
    .min(1, 'Description is required')
    .trim(),

  requirements: z.array(z.string().trim())
    .min(1, 'At least one requirement is needed'),

  resources: z.array(z.string().trim())
    .optional(),

  rewards: z.string().trim().optional(),

  deadline: z.string()
    .refine(val => new Date(val) > new Date(), {
      message: 'Deadline must be in the future'
    })
    .optional(),

  reviewDeadline: z.string()
    .refine(val => new Date(val) > new Date(), {
      message: 'Review deadline must be in the future'
    })
    .optional(),

  difficulty: z.enum(Object.values(ChallengeDifficulty) as [string, ...string[]]),

  category: z.array(z.string().trim())
    .min(1, 'At least one category is required'),

  maxParticipants: z.number().int().min(1).optional(),

  tags: z.array(z.string().trim()).optional(),

  maxApprovedSolutions: z.number().int().min(1).default(5),

  visibility: z.enum(Object.values(ChallengeVisibility) as [string, ...string[]])
    .default(ChallengeVisibility.PUBLIC),

  allowedInstitutions: z.array(z.string().trim())
    .optional(),

  isCompanyVisible: z.boolean()
    .optional()
});

// Create the schema with conditional validations using superRefine
export const createChallengeSchemaWithRefinements = createChallengeSchema.superRefine((data, ctx) => {
  // Private challenges must specify allowed institutions
  if (data.visibility === ChallengeVisibility.PRIVATE) {
    if (!data.allowedInstitutions || data.allowedInstitutions.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'At least one institution must be specified for private challenges',
        path: ['allowedInstitutions']
      });
    }
  }
  if (data.reviewDeadline && data.deadline) {
    if (new Date(data.reviewDeadline) <= new Date(data.deadline)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Review deadline must be after submission deadline',
        path: ['reviewDeadline']
      });
    }
  }

  // Anonymous challenges must hide company
  if (data.visibility === ChallengeVisibility.ANONYMOUS) {
    if (data.isCompanyVisible === true) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Company must be hidden for anonymous challenges',
        path: ['isCompanyVisible']
      });
    }
  }
});

/**
 * Zod schema for updating a challenge
 */
export const updateChallengeSchema = createChallengeSchema
  .partial() // Make all fields optional
  .superRefine((data, ctx) => {
    // Ensure at least one field is being updated
    if (Object.keys(data).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'At least one field is required for update'
      });
    }

    // Reapply conditional validations
    if (data.visibility === ChallengeVisibility.PRIVATE) {
      if (!data.allowedInstitutions || data.allowedInstitutions.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'At least one institution must be specified for private challenges',
          path: ['allowedInstitutions']
        });
      }
    }

    if (data.visibility === ChallengeVisibility.ANONYMOUS) {
      if (data.isCompanyVisible === true) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Company must be hidden for anonymous challenges',
          path: ['isCompanyVisible']
        });
      }
    }
  });