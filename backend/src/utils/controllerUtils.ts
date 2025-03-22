import { Request, Response, NextFunction } from 'express';
import { HTTP_STATUS } from '../constants';
import { ApiError } from './ApiError';
import { logger } from './logger';

/**
 * Standard controller response format
 */
interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: any[];
  meta?: Record<string, any>;
}

// MongoDB error types
interface MongoError extends Error {
  code?: number;
  keyValue?: Record<string, any>;
}

interface ValidationError extends Error {
  name: 'ValidationError';
  errors: Record<string, { path: string; message: string }>;
}

interface CastError extends Error {
  name: 'CastError';
  path?: string;
  value?: any;
}

/**
 * Send a success response
 * 
 * @param res - Express response object
 * @param data - Data to send in response
 * @param message - Success message
 * @param statusCode - HTTP status code (default: 200 OK)
 * @param meta - Additional metadata
 */
export const sendSuccessResponse = <T>(
  res: Response,
  data: T,
  message = 'Operation successful',
  statusCode = HTTP_STATUS.OK,
  meta?: Record<string, any>
): Response => {
  const response: ApiResponse<T> = {
    success: true,
    message,
    data,
  };

  if (meta) {
    response.meta = meta;
  }

  return res.status(statusCode).json(response);
};

/**
 * Send an error response
 * 
 * @param res - Express response object
 * @param error - Error message or object
 * @param statusCode - HTTP status code (default: 400 BAD REQUEST)
 * @param errors - Additional error details
 */
export const sendErrorResponse = (
  res: Response,
  error: string | Error,
  statusCode = HTTP_STATUS.BAD_REQUEST,
  errors?: any[]
): Response => {
  const message = error instanceof Error ? error.message : error;
  
  const response: ApiResponse = {
    success: false,
    message
  };

  if (errors) {
    response.errors = errors;
  }

  return res.status(statusCode).json(response);
};

/**
 * Standard error handler for controller methods
 * 
 * @param fn - Controller function
 * @returns Express middleware function with error handling
 */
export const handleControllerError = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await fn(req, res, next);
    } catch (error: unknown) {
      // Log the error
      logger.error(`Controller error: ${error instanceof Error ? error.stack : String(error)}`);
      
      // Handle ApiError instances
      if (error instanceof ApiError) {
        sendErrorResponse(
          res,
          error.message,
          error.statusCode,
          error.details ? [error.details] : undefined
        );
        return;
      }
      
      // Handle MongoDB validation errors
      if (error instanceof Error && error.name === 'ValidationError') {
        const validationError = error as ValidationError;
        const errors = Object.values(validationError.errors).map((err) => ({
          field: err.path,
          message: err.message
        }));
        
        sendErrorResponse(
          res,
          'Validation error',
          HTTP_STATUS.UNPROCESSABLE_ENTITY,
          errors
        );
        return;
      }
      
      // Handle MongoDB CastError (invalid ObjectId, etc.)
      if (error instanceof Error && error.name === 'CastError') {
        const castError = error as CastError;
        sendErrorResponse(
          res,
          `Invalid ${castError.path || 'value'}: ${castError.value}`,
          HTTP_STATUS.BAD_REQUEST
        );
        return;
      }
      
      // Handle MongoDB duplicate key error
      if (error instanceof Error && 'code' in error && error.code === 11000) {
        const mongoError = error as MongoError;
        if (mongoError.keyValue) {
          const field = Object.keys(mongoError.keyValue)[0];
          sendErrorResponse(
            res,
            `${field} already exists`,
            HTTP_STATUS.CONFLICT
          );
          return;
        }
      }
      
      // Default error response for unexpected errors
      sendErrorResponse(
        res,
        error instanceof Error ? error.message : 'Internal server error',
        HTTP_STATUS.INTERNAL_SERVER_ERROR
      );
    }
  };
};