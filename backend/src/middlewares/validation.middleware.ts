import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/ApiError';

/**
 * Validation middleware using Zod schemas
 */
export const validateRequest = (schema: z.ZodType<any, any>) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate request body against schema
      const result = schema.safeParse(req.body);
      
      if (!result.success) {
        const errors = result.error.errors.map(err => ({
          path: err.path.join('.'),
          message: err.message
        }));
        
        return next(
          new ApiError(
            HTTP_STATUS.UNPROCESSABLE_ENTITY, 
            'Validation failed', 
            true, 
            undefined, 
            { errors }
          )
        );
      }
      
      // If validation succeeded, update request body with parsed data
      req.body = result.data;
      next();
    } catch (error) {
      next(new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Validation error'));
    }
  };
};

/**
 * Sanitize input to prevent XSS attacks
 */
export const sanitizeInput = (req: Request, _res: Response, next: NextFunction) => {
  if (req.body) {
    // Process each field with a sanitizer function (implement as needed)
    // This is a simplified example - use a library like DOMPurify in production
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key]
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
      }
    });
  }
  
  next();
};