import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { ApiResponse } from '../utils/ApiResponse';
import { logger } from '../utils/logger';
import { HTTP_STATUS } from '../constants';
import mongoose from 'mongoose';

/**
 * Handle 404 errors for routes not found
 */
export const notFoundHandler = (req: Request, res: Response, next: NextFunction): void => {
    next(new ApiError(404, `Cannot find ${req.originalUrl} on this server!`));
};

/**
 * Global error handler middleware
 * Important: Express error handlers must have exactly 4 parameters
 */
export const errorHandler = (
  err: any,
  req: Request, 
  res: Response, 
  next: NextFunction
): void => {
  // Log error with request ID
  logger.error(`[${req.method}] ${req.path} - Error:`, {
    requestId: req.id,
    errorMessage: err.message,
    stack: err.stack,
    body: req.body
  });
  
  // Default error
  let statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let message = 'Something went wrong';
  let isOperational = false;
  let details: Record<string, any> | undefined;
  
  // Handle ApiErrors
  if (err instanceof ApiError) {
    statusCode = err.statusCode;
    message = err.message;
    isOperational = err.isOperational;
    details = err.details;
    
    // Return proper response for API errors
    res.status(statusCode).json(
      ApiResponse.error(message, { 
        isOperational, 
        errorCode: err.errorCode,
        requestId: req.id,
        ...details
      })
    );
    return;
  }
  
  // Handle Mongoose validation errors
  if (err instanceof mongoose.Error.ValidationError) {
    statusCode = HTTP_STATUS.UNPROCESSABLE_ENTITY;
    message = 'Validation error';
    isOperational = true;
    
    const validationErrors: Record<string, string> = {};
    for (const field in err.errors) {
      validationErrors[field] = err.errors[field].message;
    }
    
    res.status(statusCode).json(
      ApiResponse.error(message, { 
        isOperational,
        requestId: req.id,
        errors: validationErrors 
      })
    );
    return;
  }
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    res.status(HTTP_STATUS.UNAUTHORIZED).json(
      ApiResponse.error('Invalid token', { 
        isOperational: true,
        requestId: req.id 
      })
    );
    return;
  }
  
  if (err.name === 'TokenExpiredError') {
    res.status(HTTP_STATUS.UNAUTHORIZED).json(
      ApiResponse.error('Token expired', { 
        isOperational: true,
        requestId: req.id 
      })
    );
    return;
  }
  
  // Handle unknown errors in production
  if (process.env.NODE_ENV === 'production') {
    // Don't expose error details in production
    res.status(statusCode).json(
      ApiResponse.error(isOperational ? message : 'Internal server error', {
        requestId: req.id
      })
    );
    return;
  }
  
  // Return detailed error in development
  res.status(statusCode).json(
    ApiResponse.error(message, {
      stack: err.stack,
      isOperational,
      requestId: req.id
    })
  );
};