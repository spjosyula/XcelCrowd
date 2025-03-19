import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { HTTP_STATUS, SolutionStatus } from '../models/interfaces';

/**
 * Validation schema for submitting a solution, used JOI can convert to zod
 */
const submitSolutionSchema = Joi.object({
  challengeId: Joi.string().required()
    .messages({
      'string.empty': 'Challenge ID is required',
      'any.required': 'Challenge ID is required'
    }),
  
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
  
  submissionUrl: Joi.string().required().trim()
    .uri({ scheme: ['http', 'https'] })
    .messages({
      'string.empty': 'Submission URL is required',
      'string.uri': 'Submission URL must be a valid URL',
      'any.required': 'Submission URL is required'
    })
});

/**
 * Validation schema for updating a solution
 */
const updateSolutionSchema = Joi.object({
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
  
  submissionUrl: Joi.string().required().trim()
    .uri({ scheme: ['http', 'https'] })
    .messages({
      'string.empty': 'Submission URL is required',
      'string.uri': 'Submission URL must be a valid URL',
      'any.required': 'Submission URL is required'
    })
});

/**
 * Validation schema for reviewing a solution
 */
const reviewSolutionSchema = Joi.object({
  status: Joi.string().valid(SolutionStatus.APPROVED, SolutionStatus.REJECTED).required()
    .messages({
      'string.empty': 'Status is required',
      'any.only': 'Status must be either approved or rejected',
      'any.required': 'Status is required'
    }),
  
  feedback: Joi.string().trim()
    .when('status', {
      is: SolutionStatus.REJECTED,
      then: Joi.string().required()
        .messages({
          'string.empty': 'Feedback is required for rejected solutions',
          'any.required': 'Feedback is required for rejected solutions'
        })
    }),
  
  score: Joi.number().min(0).max(100)
    .when('status', {
      is: SolutionStatus.APPROVED,
      then: Joi.number().required()
        .messages({
          'any.required': 'Score is required for approved solutions'
        })
    })
    .messages({
      'number.min': 'Score cannot be negative',
      'number.max': 'Score cannot exceed 100'
    })
});

/**
 * Middleware to validate solution submission
 */
export const validateSubmitSolution = (req: Request, res: Response, next: NextFunction): void => {
  const { error } = submitSolutionSchema.validate(req.body, { abortEarly: false });
  
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
 * Middleware to validate solution update
 */
export const validateUpdateSolution = (req: Request, res: Response, next: NextFunction): void => {
  const { error } = updateSolutionSchema.validate(req.body, { abortEarly: false });
  
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
 * Middleware to validate solution review
 */
export const validateReviewSolution = (req: Request, res: Response, next: NextFunction): void => {
  const { error } = reviewSolutionSchema.validate(req.body, { abortEarly: false });
  
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