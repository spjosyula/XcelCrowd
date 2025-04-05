import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from '../utils/logger';

/**
 * Type for validation source locations in request
 */
export type ValidationSource = 'body' | 'query' | 'params' | 'headers' | 'cookies' | 'all';

/**
 * Options for validation middleware
 */
export interface ValidationOptions {
  /**
   * Where to look for data to validate
   * @default 'body'
   */
  source?: ValidationSource | ValidationSource[];
  
  /**
   * Whether to strip unknown properties
   * @default true
   */
  stripUnknown?: boolean;
}

/**
 * Middleware factory to validate request data against a Zod schema
 * 
 * @param schema - Zod schema for validation
 * @param options - Validation options
 */
export const validateRequest = <T extends Record<string, any>>(
  schema: ZodSchema<T>,
  options: ValidationOptions = { source: 'body', stripUnknown: true }
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // Determine which parts of the request to validate
      const sources = Array.isArray(options.source) 
        ? options.source 
        : options.source === 'all' 
          ? ['body', 'query', 'params'] 
          : [options.source || 'body'];
      
      // Build data object from specified sources
      const dataToValidate = sources.reduce<Record<string, any>>((acc, source) => {
        if (source === 'body') return { ...acc, ...req.body };
        if (source === 'query') return { ...acc, ...req.query };
        if (source === 'params') return { ...acc, ...req.params };
        if (source === 'headers') return { ...acc, ...req.headers };
        if (source === 'cookies') return { ...acc, ...req.cookies };
        return acc;
      }, {});
      
      // Validate against the schema
      const parsedData = schema.parse(dataToValidate);
      
      // Add validated data to request
      req.validatedData = parsedData;
      
      // Apply validated data back to request (optional based on source)
      if (sources.includes('body')) {
        req.body = parsedData;
      }
      
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        // Format Zod validation errors
        const validationErrors = error.errors.map((err) => ({
          path: err.path.join('.'),
          message: err.message,
          code: err.code
        }));
        
        logger.debug('Validation failed', { errors: validationErrors });
        
        // Fix: Pass validation errors as part of an object structure to match Record<string, any>
        next(new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Validation failed',
          true,
          'VALIDATION_ERROR',
          { errors: validationErrors } // Wrap in an object to satisfy Record<string, any>
        ));
      } else {
        logger.error('Unexpected validation error', error);
        next(new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid request data'));
      }
    }
  };
};

// Extend Express Request interface to include validated data
declare global {
  namespace Express {
    interface Request {
      validatedData?: Record<string, any>;
    }
  }
}