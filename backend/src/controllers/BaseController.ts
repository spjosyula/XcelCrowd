import { Response } from 'express';
import { AuthRequest } from '../types/request.types';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { UserRole } from '../models/interfaces';
import { AuthorizationService, OwnershipCheck, RelationshipCheck } from '../utils/authorization';
import { Types } from 'mongoose';
import { logger } from '../utils/logger';
import { PaginationResult } from '../utils/paginationUtils';
import { validateObjectId as validateMongoId } from '../utils/mongoUtils';

/**
 * Base controller with standardized responses and authorization methods
 */
export class BaseController {
  /**
 * Verify that the user is authorized based on role
 * 
 * @param req - The authenticated request object
 * @param allowedRoles - Roles permitted to perform this action
 * @param actionDescription - Optional description for logging and error messages
 * @throws {ApiError} HTTP 401 if unauthenticated, HTTP 403 if unauthorized
 */
  protected verifyAuthorization(
    req: AuthRequest,
    allowedRoles?: UserRole[],
    actionDescription?: string
  ): void {
    try {
      // Perform authentication check
      if (!req.user) {
        const error = new ApiError(
          HTTP_STATUS.UNAUTHORIZED,
          'Authentication required',
          true,
          'AUTHENTICATION_REQUIRED'
        );
        logger.warn('Authentication failed: No user in request', {
          path: req.path,
          method: req.method
        });
        throw error;
      }

      // Skip role check if no roles specified
      if (!allowedRoles || allowedRoles.length === 0) {
        return;
      }

      // Perform role check
      const userRole = req.user.role as UserRole;
      if (!allowedRoles.includes(userRole)) {
        const action = actionDescription ? ` for ${actionDescription}` : '';
        const error = new ApiError(
          HTTP_STATUS.FORBIDDEN,
          `Access denied. You need ${allowedRoles.length > 1 ?
            'one of these roles: ' + allowedRoles.join(', ') :
            'the ' + allowedRoles[0] + ' role'}${action}`,
          true,
          'INSUFFICIENT_ROLE'
        );

        logger.warn(`Authorization failed: User ${req.user.userId} with role ${userRole} attempted restricted action${action}`, {
          userId: req.user.userId,
          userRole,
          allowedRoles,
          action: actionDescription || req.path,
          method: req.method
        });

        throw error;
      }

      // Log successful authorization for sensitive operations (optional)
      if (allowedRoles.includes(UserRole.ADMIN)) {
        logger.info(`Admin authorization successful: User ${req.user.userId}${actionDescription ? ' ' + actionDescription : ''}`, {
          userId: req.user.userId,
          action: actionDescription || req.path
        });
      }
    } catch (error) {
      // Ensure we're not swallowing any errors
      if (error instanceof ApiError) {
        throw error;
      }
      // Convert unknown errors to ApiError
      logger.error('Unexpected error during authorization', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Authorization check failed',
        true,
        'AUTHORIZATION_ERROR'
      );
    }
  }

  /**
   * Get the profile ID for a user with a specific role
   */
  protected async getUserProfileId(req: AuthRequest, expectedRole: UserRole): Promise<string> {
    return AuthorizationService.getUserProfileId(req, expectedRole);
  }

  /**
   * Verify that the authenticated user owns a resource
   */
  protected async verifyResourceOwnership(
    req: AuthRequest,
    resource: any,
    ownerIdField: string,
    ownerRole: UserRole,
    message?: string
  ): Promise<void> {
    const ownershipCheck: OwnershipCheck = {
      resource,
      resourceOwnerIdField: ownerIdField,
      ownerRole,
      message
    };

    await AuthorizationService.verifyOwnership(req, ownershipCheck);
  }

  /**
   * Verify a custom relationship between user and resource
   */
  protected async verifyRelationship(
    req: AuthRequest,
    resource: any,
    check: (req: AuthRequest, resource: any) => boolean | Promise<boolean>,
    message: string
  ): Promise<void> {
    const relationshipCheck: RelationshipCheck = {
      check,
      message
    };

    await AuthorizationService.verifyRelationship(req, resource, relationshipCheck);
  }

  /**
   * Comprehensive authorization check
   */
  protected async authorize(
    req: AuthRequest,
    options: {
      allowedRoles?: UserRole[];
      resource?: any;
      ownerIdField?: string;
      ownerRole?: UserRole;
      relationshipCheck?: (req: AuthRequest, resource: any) => boolean | Promise<boolean>;
      failureMessage?: string;
    }
  ): Promise<void> {
    const {
      allowedRoles,
      resource,
      ownerIdField,
      ownerRole,
      relationshipCheck,
      failureMessage
    } = options;

    // Prepare checks
    const authOptions: {
      allowedRoles?: UserRole[];
      ownershipCheck?: OwnershipCheck;
      relationshipCheck?: RelationshipCheck;
    } = {};

    if (allowedRoles) {
      authOptions.allowedRoles = allowedRoles;
    }

    if (resource && ownerIdField && ownerRole) {
      authOptions.ownershipCheck = {
        resource,
        resourceOwnerIdField: ownerIdField,
        ownerRole,
        message: failureMessage
      };
    }

    if (resource && relationshipCheck) {
      authOptions.relationshipCheck = {
        check: relationshipCheck,
        message: failureMessage || 'You do not have permission to access this resource'
      };
    }

    await AuthorizationService.authorize(req, authOptions);
  }

  /**
   * Validate that a string is a valid MongoDB ObjectId
   * @deprecated Use validateObjectId from mongoUtils instead
   */
  protected validateObjectId(id: string, resourceName: string): void {
    // Delegate to the centralized implementation
    validateMongoId(id, resourceName);
  }

  /**
   * Log an action for audit purposes
   */
  protected logAction(action: string, userId: string, metadata?: Record<string, any>): void {
    logger.info(`Action ${action} performed by user ${userId}`, { action, userId, ...metadata });
  }

  /**
   * Send a success response
   */
  protected sendSuccess(
    res: Response,
    data: any,
    message: string = 'Operation successful',
    statusCode: number = HTTP_STATUS.OK
  ): void {
    res.status(statusCode).json({
      success: true,
      message,
      data
    });
  }

  /**
   * Send a paginated success response
   */
  protected sendPaginatedSuccess<T>(
    res: Response,
    result: PaginationResult<T>,
    message: string = 'Operation successful',
    statusCode: number = HTTP_STATUS.OK
  ): void {
    res.status(statusCode).json({
      success: true,
      message,
      data: result.data,
      meta: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        totalPages: result.totalPages,
        hasNextPage: result.hasNextPage,
        hasPrevPage: result.hasPrevPage
      }
    });
  }
}