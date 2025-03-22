import { Request, Response, NextFunction } from 'express';
import { ApiError } from './ApiError';
import { logger } from './logger';
import { HTTP_STATUS } from '../constants';

/**
 * Type for controller request handler functions
 */
export type RequestHandler<Req = Request, Res = Response> = (
  req: Req, 
  res: Res,
  next: NextFunction
) => Promise<void> | void;

/**
 * Wraps controller methods to handle exceptions consistently
 * 
 * @param fn - The controller function to wrap
 * @returns Wrapped function that catches and forwards errors to error middleware
 */
export function catchAsync<Req = Request, Res = Response>(
  fn: RequestHandler<Req, Res>
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Type assertion to handle custom request types
      await fn(req as unknown as Req, res as Res, next);
    } catch (error) {
      // Log the error
      logger.error('Controller error:', {
        path: req.url,
        method: req.method,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      // Forward to error handler middleware
      next(error);
    }
  };
}

/**
 * Legacy function to maintain backward compatibility
 * @deprecated Use catchAsync instead
 */
export const handleControllerError = catchAsync;

/**
 * Legacy function to maintain backward compatibility
 * @deprecated Use BaseController.sendSuccess instead
 */
export function sendSuccessResponse<T>(
  res: Response, 
  data: T, 
  message: string, 
  statusCode: number = HTTP_STATUS.OK,
  meta?: Record<string, any>
): void {
  res.status(statusCode).json({
    success: true,
    message,
    data,
    ...(meta && { meta })
  });
}