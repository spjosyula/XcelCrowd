import { Response } from 'express';
import { HTTP_STATUS } from '../constants';
import { ApiResponse } from '../utils/ApiResponse';
import { logger } from '../utils/logger';
import { AuthRequest } from '../types/request.types';
import { ApiError } from '../utils/ApiError';
import { UserRole } from '../models/interfaces';

/**
 * Base controller with shared response handling methods and utilities
 * All controllers should extend this class for consistency
 */
export abstract class BaseController {
  /**
   * Send success response with standardized format
   */
  protected sendSuccess<T>(
    res: Response, 
    data: T, 
    message: string, 
    statusCode: number = HTTP_STATUS.OK,
    meta?: Record<string, any>
  ): void {
    res.status(statusCode).json(
      ApiResponse.success(data, message, meta)
    );
  }
  
  /**
   * Send paginated response with standardized format
   */
  protected sendPaginatedSuccess<T>(
    res: Response,
    data: T[],
    message: string,
    {
      total,
      page,
      limit
    }: {
      total: number;
      page: number;
      limit: number;
    },
    statusCode: number = HTTP_STATUS.OK
  ): void {
    this.sendSuccess(
      res,
      data,
      message,
      statusCode,
      {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    );
  }

  /**
   * Verify user is authenticated and optionally has required role
   * Throws ApiError if not authorized
   */
  protected verifyAuthorization(req: AuthRequest, allowedRoles?: UserRole[]): void {
    if (!req.user) {
      throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication required');
    }

    if (allowedRoles && !allowedRoles.includes(req.user.role as UserRole)) {
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN, 
        'You do not have permission to perform this action'
      );
    }
  }

  /**
   * Get user profile ID with verification
   * Throws ApiError if profile not found
   */
  protected getUserProfileId(req: AuthRequest, role?: UserRole): string {
    this.verifyAuthorization(req, role ? [role] : undefined);
    
    const profileId = req.user?.profile?.toString();
    
    if (!profileId) {
      throw new ApiError(
        HTTP_STATUS.UNAUTHORIZED, 
        `${req.user?.role || 'User'} profile not found`
      );
    }
    
    return profileId;
  }

  /**
   * Validate MongoDB ObjectId
   * Throws ApiError if invalid
   */
  protected validateObjectId(id: string, entityName: string = 'entity'): void {
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, `Invalid ${entityName} ID format`);
    }
  }

  /**
   * Log controller actions with standardized format
   */
  protected logAction(action: string, userId?: string, details?: Record<string, any>): void {
    logger.info({
      action,
      userId: userId || 'anonymous',
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}