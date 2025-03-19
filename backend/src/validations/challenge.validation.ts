import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { HTTP_STATUS, ChallengeStatus, ChallengeDifficulty, ChallengeVisibility } from '../models/interfaces';

/**
 * Validation schema for creating a challenge, used JOI, can convert to zod
 */
const createChallengeSchema = Joi.object({
  title: Joi.string().required().max(100).trim()
    .messages({
      'string.empty': 'Title is required',
      'string.max': 'Title cannot exceed 100 characters',
      'any.required': 'Title is required'
    }),
  
  description: Joi.string().required().trim()
    .messages({
      'string.empty': 'Description is required',
      'any.required': 'Description is required'
    }),
  
  requirements: Joi.array().items(Joi.string().trim()).min(1).required()
    .messages({
      'array.min': 'At least one requirement is needed',
      'any.required': 'Requirements are required'
    }),
  
  resources: Joi.array().items(Joi.string().trim()),
  
  rewards: Joi.string().trim(),
  
  deadline: Joi.date().greater('now')
    .messages({
      'date.greater': 'Deadline must be in the future'
    }),
  
  status: Joi.string().valid(...Object.values(ChallengeStatus)).default(ChallengeStatus.DRAFT)
    .messages({
      'any.only': 'Invalid challenge status'
    }),
  
  difficulty: Joi.string().valid(...Object.values(ChallengeDifficulty)).required()
    .messages({
      'any.only': 'Invalid difficulty level',
      'any.required': 'Difficulty level is required'
    }),
  
  category: Joi.array().items(Joi.string().trim()).min(1).required()
    .messages({
      'array.min': 'At least one category is required',
      'any.required': 'Category is required'
    }),
  
  maxParticipants: Joi.number().integer().min(1).optional()
    .messages({
      'number.min': 'Maximum participants must be at least 1'
    }),
  
  tags: Joi.array().items(Joi.string().trim()),
  
  maxApprovedSolutions: Joi.number().integer().min(1).default(5)
    .messages({
      'number.min': 'Maximum approved solutions must be at least 1'
    }),
  
  visibility: Joi.string().valid(...Object.values(ChallengeVisibility)).default(ChallengeVisibility.PUBLIC)
    .messages({
      'any.only': 'Invalid visibility setting'
    }),
  
  allowedInstitutions: Joi.array().items(Joi.string().trim())
    .when('visibility', {
      is: ChallengeVisibility.PRIVATE,
      then: Joi.array().min(1).required()
        .messages({
          'array.min': 'At least one institution must be specified for private challenges',
          'any.required': 'Allowed institutions are required for private challenges'
        })
    }),
  
  isCompanyVisible: Joi.boolean()
    .when('visibility', {
      is: ChallengeVisibility.ANONYMOUS,
      then: Joi.boolean().valid(false)
        .messages({
          'any.only': 'Company must be hidden for anonymous challenges'
        })
    })
});

/**
 * Validation schema for updating a challenge
 */
const updateChallengeSchema = Joi.object({
  title: Joi.string().max(100).trim()
    .messages({
      'string.max': 'Title cannot exceed 100 characters'
    }),
  
  description: Joi.string().trim(),
  
  requirements: Joi.array().items(Joi.string().trim()).min(1)
    .messages({
      'array.min': 'At least one requirement is needed'
    }),
  
  resources: Joi.array().items(Joi.string().trim()),
  
  rewards: Joi.string().trim(),
  
  deadline: Joi.date().greater('now')
    .messages({
      'date.greater': 'Deadline must be in the future'
    }),
  
  status: Joi.string().valid(...Object.values(ChallengeStatus))
    .messages({
      'any.only': 'Invalid challenge status'
    }),
  
  difficulty: Joi.string().valid(...Object.values(ChallengeDifficulty))
    .messages({
      'any.only': 'Invalid difficulty level'
    }),
  
  category: Joi.array().items(Joi.string().trim()).min(1)
    .messages({
      'array.min': 'At least one category is required'
    }),
  
  maxParticipants: Joi.number().integer().min(1)
    .messages({
      'number.min': 'Maximum participants must be at least 1'
    }),
  
  tags: Joi.array().items(Joi.string().trim()),
  
  maxApprovedSolutions: Joi.number().integer().min(1)
    .messages({
      'number.min': 'Maximum approved solutions must be at least 1'
    }),
  
  visibility: Joi.string().valid(...Object.values(ChallengeVisibility))
    .messages({
      'any.only': 'Invalid visibility setting'
    }),
  
  allowedInstitutions: Joi.array().items(Joi.string().trim())
    .when('visibility', {
      is: ChallengeVisibility.PRIVATE,
      then: Joi.array().min(1)
        .messages({
          'array.min': 'At least one institution must be specified for private challenges'
        })
    }),
  
  isCompanyVisible: Joi.boolean()
    .when('visibility', {
      is: ChallengeVisibility.ANONYMOUS,
      then: Joi.boolean().valid(false)
        .messages({
          'any.only': 'Company must be hidden for anonymous challenges'
        })
    })
}).min(1) // At least one field must be provided
  .messages({
    'object.min': 'At least one field is required for update'
  });

/**
 * Middleware to validate challenge creation
 */
export const validateCreateChallenge = (req: Request, res: Response, next: NextFunction): void => {
  const { error } = createChallengeSchema.validate(req.body, { abortEarly: false });
  
  if (error) {
    const errorMessages = error.details.map(detail => detail.message);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errors: errorMessages
    });
    return;
  }
  
  next();
};

/**
 * Middleware to validate challenge update
 */
export const validateUpdateChallenge = (req: Request, res: Response, next: NextFunction): void => {
  const { error } = updateChallengeSchema.validate(req.body, { abortEarly: false });
  
  if (error) {
    const errorMessages = error.details.map(detail => detail.message);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: 'Validation failed',
      errors: errorMessages
    });
    return;
  }
  
  next();
}; 