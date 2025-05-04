import mongoose, { Types, Document } from 'mongoose';
import { User, IUser, UserRole, StudentProfile, Solution, CompanyProfile, ArchitectProfile } from '../models';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from '../utils/logger';
import { executePaginatedQuery, PaginationOptions, PaginationResult } from '../utils/paginationUtils';
import { BaseService } from './BaseService';
import { escapeRegExp } from 'lodash';

/**
 * Extended interface for user documents from MongoDB
 * Combining properties from IUser and Mongoose Document
 */
export interface UserDocument extends Omit<Document, '_id'>, IUser {
  _id: Types.ObjectId;  // Explicitly define _id as ObjectId
  comparePassword(password: string): Promise<boolean>;
  generateEmailVerificationToken(): string;  // Method to generate email verification token
  verifyEmailToken(otp: string): boolean;  // Method to verify email token
  generatePasswordResetToken(): string;  // Method to generate password reset token
  verifyPasswordResetToken(otp: string): boolean;  // Method to verify password reset token
}

export interface CreateUserDTO {
  email: string;
  password: string;
  role: UserRole;
}

export interface UpdateUserDTO {
  email?: string;
  password?: string;
}

/**
 * User service for handling user-related operations
 */
export class UserService extends BaseService {
  /**
   * Create a new user
   */
  public async createUser(userData: CreateUserDTO): Promise<UserDocument> {
    try {
      return await this.withTransaction(async (session) => {
        // Validate input data
        if (!userData.email || !userData.password || !Object.values(UserRole).includes(userData.role)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Invalid user data. Email, password and valid role are required',
            true,
            'INVALID_USER_DATA'
          );
        }

        // Check if user with email already exists
        const existingUser = await User.findOne({ email: userData.email }).session(session);
        if (existingUser) {
          throw new ApiError(
            HTTP_STATUS.CONFLICT,
            'Email already in use',
            true,
            'EMAIL_ALREADY_EXISTS'
          );
        }

        // Create new user with transaction support
        const users = await User.create([userData], { session });
        const user = users[0] as unknown as UserDocument;

        logger.info(`User created successfully with ID: ${user._id}`, {
          userId: user._id.toString(),
          email: user.email,
          role: user.role
        });

        return user;
      });
    } catch (error) {
      logger.error(`Error creating user: ${error instanceof Error ? error.message : String(error)}`, {
        email: userData.email,
        role: userData.role,
        stack: error instanceof Error ? error.stack : undefined
      });

      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to create user',
        true,
        'USER_CREATION_ERROR'
      );
    }
  }

  /**
   * Get user by ID
   */
  public async getUserById(userId: string): Promise<UserDocument> {
    try {
      if (!Types.ObjectId.isValid(userId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
      }

      return user as unknown as UserDocument;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve user');
    }
  }

  /**
   * Get user by email
   */
  public async getUserByEmail(email: string): Promise<UserDocument> {
    try {
      const user = await User.findOne({ email }).select('+password');
      if (!user) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
      }

      return user as unknown as UserDocument;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve user');
    }
  }

  /**
   * Get users with pagination and filtering
   * @param filters - MongoDB filter object
   * @param options - Pagination and sorting options
   */
  public async getUsers(
    filters: Record<string, any> = {},
    options: PaginationOptions
  ): Promise<PaginationResult<IUser>> {
    try {
      return await executePaginatedQuery<IUser>(
        User,
        filters,
        {
          page: options.page || 1,
          limit: options.limit || 10,
          sortBy: options.sortBy || 'createdAt',
          sortOrder: options.sortOrder || 'desc'
        }
      );
    } catch (error) {
      logger.error(
        `Error retrieving users: ${error instanceof Error ? error.message : String(error)}`,
        { filters, error }
      );

      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve users');
    }
  }

  /**
   * Update user
   */
  public async updateUser(userId: string, updateData: UpdateUserDTO): Promise<IUser> {
    try {
      return await this.withTransaction(async (session) => {
        if (!Types.ObjectId.isValid(userId)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Invalid user ID',
            true,
            'INVALID_USER_ID'
          );
        }

        // Check if the user exists
        const existingUser = await User.findById(userId).session(session);
        if (!existingUser) {
          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            'User not found',
            true,
            'USER_NOT_FOUND'
          );
        }

        // Handle email update - check for uniqueness
        if (updateData.email && updateData.email !== existingUser.email) {
          const emailExists = await User.findOne({
            email: updateData.email,
            _id: { $ne: userId }
          }).session(session);

          if (emailExists) {
            throw new ApiError(
              HTTP_STATUS.CONFLICT,
              'Email already in use by another account',
              true,
              'EMAIL_ALREADY_EXISTS'
            );
          }
        }

        // Update the user with transaction support
        const updatedUser = await User.findByIdAndUpdate(
          userId,
          updateData,
          {
            new: true,
            runValidators: true,
            session
          }
        );

        if (!updatedUser) {
          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            'User not found after update',
            true,
            'USER_UPDATE_FAILED'
          );
        }

        logger.info(`User ${userId} updated successfully`, {
          userId,
          updatedFields: Object.keys(updateData).join(',')
        });

        return updatedUser;
      });
    } catch (error) {
      logger.error(`Error updating user: ${error instanceof Error ? error.message : String(error)}`, {
        userId,
        updateFields: Object.keys(updateData).join(','),
        stack: error instanceof Error ? error.stack : undefined
      });

      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to update user',
        true,
        'USER_UPDATE_ERROR'
      );
    }
  }

  /**
   * Delete user and all associated data (cascade delete)
   */
  public async deleteUser(userId: string): Promise<void> {
    try {
      await this.withTransaction(async (session) => {
        if (!Types.ObjectId.isValid(userId)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Invalid user ID',
            true,
            'INVALID_USER_ID'
          );
        }

        // Get user with role to determine what to delete
        const user = await User.findById(userId).session(session);
        if (!user) {
          throw new ApiError(
            HTTP_STATUS.NOT_FOUND,
            'User not found',
            true,
            'USER_NOT_FOUND'
          );
        }

        // Delete associated profile based on role
        switch (user.role) {
          case UserRole.STUDENT:
            // Find student profile ID for solutions deletion
            const studentProfile = await StudentProfile.findOne({ user: userId }).session(session);
            if (studentProfile) {
              // Delete all student solutions
              await Solution.deleteMany({ student: studentProfile._id }).session(session);
              // Delete student profile
              await StudentProfile.findByIdAndDelete(studentProfile._id).session(session);
              logger.info(`Deleted student profile and ${studentProfile._id} and related solutions`);
            }
            break;
          case UserRole.COMPANY:
            const companyProfile = await CompanyProfile.findOne({ user: userId }).session(session);
            if (companyProfile) {
              // Delete company profile
              await CompanyProfile.findByIdAndDelete(companyProfile._id).session(session);
              logger.info(`Deleted company profile ${companyProfile._id}`);
              // Note: This should also handle challenge ownership transfer or deletion
              // based on business requirements
            }
            break;
          case UserRole.ARCHITECT:
            const architectProfile = await ArchitectProfile.findOne({ user: userId }).session(session);
            if (architectProfile) {
              // Delete architect profile
              await ArchitectProfile.findByIdAndDelete(architectProfile._id).session(session);
              logger.info(`Deleted architect profile ${architectProfile._id}`);
              // Note: This should also handle review reassignment if necessary
            }
            break;
          default:
            logger.warn(`Deleting user with unhandled role: ${user.role}`);
        }

        // Delete user document
        await User.findByIdAndDelete(userId).session(session);
        logger.info(`User ${userId} successfully deleted`);
      });
    } catch (error) {
      logger.error(`Error deleting user: ${error instanceof Error ? error.message : String(error)}`, {
        userId,
        stack: error instanceof Error ? error.stack : undefined
      });

      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to delete user and associated data',
        true,
        'USER_DELETION_ERROR'
      );
    }
  }

  /**
 * Search users with filtering, sanitization and pagination
 * @param options - Search and pagination options
 */
  public async searchUsers(options: {
    role?: UserRole;
    searchTerm?: string;
    pagination: PaginationOptions;
  }): Promise<PaginationResult<IUser>> {
    try {
      // Build filters object
      const filters: Record<string, any> = {};

      // Add role filter if provided
      if (options.role) {
        filters.role = options.role;
      }

      // Process search term if provided with proper validation and sanitization
      if (options.searchTerm) {
        // Validate search term length to prevent DoS attacks
        const searchString = String(options.searchTerm);
        if (searchString.length > 100) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Search term exceeds maximum allowed length',
            true,
            'SEARCH_TERM_TOO_LONG'
          );
        }

        try {
          // Safely escape special regex characters to prevent ReDoS attacks
          const sanitizedSearchTerm = escapeRegExp(searchString);

          // Apply word boundary markers for better search precision
          const safeRegex = new RegExp(`\\b${sanitizedSearchTerm}`, 'i');

          // Apply search to relevant fields
          filters.$or = [
            { email: safeRegex },
            { name: safeRegex }
          ];

          // Security audit logging for search operations
          logger.debug(`User search performed with term: ${searchString.substring(0, 20)}${searchString.length > 20 ? '...' : ''}`);
        } catch (error) {
          // Log potential attack attempts
          logger.warn(`Potentially malicious search term rejected: ${searchString.substring(0, 20)}...`, {
            error: error instanceof Error ? error.message : String(error)
          });

          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            'Invalid search term',
            true,
            'INVALID_SEARCH_TERM'
          );
        }
      }

      // Execute paginated query with all filters
      return await executePaginatedQuery<IUser>(
        User,
        filters,
        options.pagination
      );
    } catch (error) {
      logger.error(
        `Error searching users: ${error instanceof Error ? error.message : String(error)}`,
        {
          searchTerm: options.searchTerm?.substring(0, 20),
          role: options.role,
          page: options.pagination.page
        }
      );

      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to search users',
        true,
        'USER_SEARCH_ERROR'
      );
    }
  }
}

// Create and export singleton instance
export const userService = new UserService();