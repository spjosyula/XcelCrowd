import { Request, Response, NextFunction } from 'express';
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/ApiError';
import { ApiResponse } from '../utils/ApiResponse';
import { logger } from '../utils/logger';
import mongoose from 'mongoose';

/**
 * Handle 404 errors for routes that don't exist
 */
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
  const error = new ApiError(
    HTTP_STATUS.NOT_FOUND,
    `Cannot find ${req.originalUrl} on this server`
  );
  next(error);
};

/**
 * Global error handler middleware
 */
export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  // Log the error for debugging
  logger.error(`Error: ${err.message}`, { 
    stack: err.stack,
    path: req.path,
    method: req.method,
    requestId: req.headers['x-request-id'] || 'unknown'
  });

  // Default error values
  let statusCode = err.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR;
  let message = err.message || 'Something went wrong';
  let errorDetails = undefined;

  // Handle Mongoose validation errors
  if (err instanceof mongoose.Error.ValidationError) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'Validation Error';
    errorDetails = Object.values(err.errors).map(val => val.message);
  }

  // Handle Mongoose CastError (invalid ObjectId)
  if (err instanceof mongoose.Error.CastError) {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = `Invalid ${err.path}: ${err.value}`;
  }

  // Handle Mongoose duplicate key error
  if (err.code === 11000) {
    statusCode = HTTP_STATUS.CONFLICT;
    const field = Object.keys(err.keyValue)[0];
    message = `Duplicate value for ${field}. This ${field} is already in use.`;
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = 'Invalid token. Please log in again.';
  }

  if (err.name === 'TokenExpiredError') {
    statusCode = HTTP_STATUS.UNAUTHORIZED;
    message = 'Your token has expired. Please log in again.';
  }

  // Handle multer file size error
  if (err.code === 'LIMIT_FILE_SIZE') {
    statusCode = HTTP_STATUS.BAD_REQUEST;
    message = 'File too large. Maximum size is 5MB.';
  }

  // Handle rate limit error
  if (err.statusCode === 429) {
    message = err.message || 'Too many requests. Please try again later.';
  }

  // Prevent leaking error details in production
  const isProduction = process.env.NODE_ENV === 'production';
  const metadata = {
    ...(errorDetails && { details: errorDetails }),
    ...((!isProduction && err.stack) && { stack: err.stack.split('\n') }),
    requestId: req.headers['x-request-id'] || undefined
  };

  // Send standardized error response
  res.status(statusCode).json(
    ApiResponse.error(message, metadata)
  );
};