import { Response, NextFunction } from 'express';
import { userService, CreateUserDTO, UpdateUserDTO, UserService } from '../services/user.service';
import { HTTP_STATUS } from '../constants';
import { catchAsync } from '../utils/catch.async';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { ApiError } from '../utils/api.error';
import { UserRole } from '../models/interfaces';
import { MongoSanitizer } from '../utils/mongo.sanitize';

/**
 * User controller for handling user-related HTTP requests
 * Extends BaseController for standardized response handling
 */
export class UserController extends BaseController {
  private readonly userService: UserService;
  constructor() {
    super();
    this.userService = userService;
  }

  /**
   * Create a new user
   * @route POST /api/users
   * @access Private - Admin only
   */
  public createUser = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify admin authorization
      this.verifyAuthorization(req, [UserRole.ADMIN]);

      const userData: CreateUserDTO = req.body;

      // Call service to create user
      const user = await this.userService.createUser(userData);

      this.logAction('user-create', req.user!.userId, {
        createdUserId: user._id!.toString(),
        role: user.role
      });

      this.sendSuccess(
        res,
        user,
        'User created successfully',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Get user by ID
   * @route GET /api/users/:id
   * @access Private - Self or Admin only
   */
  public getUserById = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);

      const { id } = req.params;

      // Validate ObjectId format using centralized utility
      MongoSanitizer.validateObjectId(id, 'user');

      // Ensure user can only access their own record, unless they're an admin
      const isSelfAccess = req.user!.userId === id;
      const isAdmin = req.user!.role === UserRole.ADMIN;

      if (!isSelfAccess && !isAdmin) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to access this user record'
        );
      }

      // Call service to get user
      const user = await this.userService.getUserById(id);

      this.logAction('user-view', req.user!.userId, { viewedUserId: id });

      this.sendSuccess(
        res,
        user,
        'User retrieved successfully'
      );
    }
  );

  /**
   * Update user
   * @route PUT /api/users/:id
   * @access Private - Self or Admin only
   */
  public updateUser = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);

      const { id } = req.params;

      // Validate ObjectId format using centralized utility
      MongoSanitizer.validateObjectId(id, 'user');

      // Ensure user can only update their own record, unless they're an admin
      const isSelfUpdate = req.user!.userId === id;
      const isAdmin = req.user!.role === UserRole.ADMIN;

      if (!isSelfUpdate && !isAdmin) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to update this user record'
        );
      }

      // Check if attempting to change role without admin rights
      if (!isAdmin && req.body.role) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'Only administrators can change user roles'
        );
      }

      const updateData: UpdateUserDTO = req.body;

      // Call service to update user
      const user = await this.userService.updateUser(id, updateData);

      this.logAction('user-update', req.user!.userId, {
        updatedUserId: id,
        isSelfUpdate,
        fields: Object.keys(updateData)
      });

      this.sendSuccess(
        res,
        user,
        'User updated successfully'
      );
    }
  );

  /**
   * Delete user
   * @route DELETE /api/users/:id
   * @access Private - Admin only
   */
  public deleteUser = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify admin authorization
      this.verifyAuthorization(req, [UserRole.ADMIN]);

      const { id } = req.params;

      // Validate ObjectId format using centralized utility
      MongoSanitizer.validateObjectId(id, 'user');

      // Prevent deletion of own account
      if (req.user!.userId === id) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You cannot delete your own admin account'
        );
      }

      // Call service to delete user
      await this.userService.deleteUser(id);

      this.logAction('user-delete', req.user!.userId, { deletedUserId: id });

      this.sendSuccess(
        res,
        null,
        'User deleted successfully'
      );
    }
  );

  /**
 * Get all users (with filtering and pagination)
 * @route GET /api/users
 * @access Private - Admin only
 */
  public getAllUsers = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify admin authorization
      this.verifyAuthorization(req, [UserRole.ADMIN]);

      // Extract query parameters
      const {
        page = '1',
        limit = '10',
        role,
        searchTerm,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Parse pagination params
      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);

      // Build search options object - delegate filtering to service layer
      const searchOptions = {
        role: role as UserRole | undefined,
        searchTerm: searchTerm as string | undefined,
        pagination: {
          page: pageNum,
          limit: limitNum,
          sortBy: sortBy as string,
          sortOrder: sortOrder as 'asc' | 'desc'
        }
      };

      try {
        // Call service to handle all business logic including search processing and pagination
        const result = await this.userService.searchUsers(searchOptions);

        this.logAction('users-list', req.user!.userId, {
          count: result.data.length,
          total: result.total,
          hasSearch: !!searchTerm
        });

        this.sendPaginatedSuccess(
          res,
          result,
          'Users retrieved successfully'
        );
      } catch (error) {
        if (error instanceof ApiError) {
          throw error;
        }
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'An error occurred while retrieving users'
        );
      }
    }
  );
}

// Export singleton instance for use in routes
export const userController = new UserController();