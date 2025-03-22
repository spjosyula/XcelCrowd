import mongoose, { Types, Document } from 'mongoose';
import { User, IUser, UserRole, StudentProfile, Solution, CompanyProfile, ArchitectProfile } from '../models';
import { ApiError } from '../utils/ApiError';
import { HTTP_STATUS } from '../constants';
import { logger } from '../utils/logger';

/**
 * Extended interface for user documents from MongoDB
 * Combining properties from IUser and Mongoose Document
 */
export interface UserDocument extends Omit<Document, '_id'>, IUser {
  _id: Types.ObjectId;  // Explicitly define _id as ObjectId
  comparePassword(password: string): Promise<boolean>;
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
export class UserService {
  /**
   * Create a new user
   */
  public async createUser(userData: CreateUserDTO): Promise<UserDocument> {
    try {
      // Check if user with email already exists
      const existingUser = await User.findOne({ email: userData.email });
      if (existingUser) {
        throw new ApiError(HTTP_STATUS.CONFLICT, 'Email already in use');
      }

      // Create new user
      const user = await User.create(userData);
      return user as UserDocument;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create user');
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

      return user as UserDocument;
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

      return user as UserDocument;
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
    options: { 
      page: number; 
      limit: number; 
      sortBy?: string; 
      sortOrder?: 'asc' | 'desc' 
    }
  ): Promise<{ users: IUser[]; total: number; page: number; limit: number }> {
    try {
      const { page = 1, limit = 10, sortBy = 'createdAt', sortOrder = 'desc' } = options;
      
      // Calculate skip value for pagination
      const skip = (page - 1) * limit;
      
      // Create sort object
      const sort: Record<string, 1 | -1> = {};
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
      
      // Execute queries in parallel for better performance
      const [users, total] = await Promise.all([
        User.find(filters)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        User.countDocuments(filters)
      ]);
      
      return {
        users,
        total,
        page,
        limit
      };
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
      if (!Types.ObjectId.isValid(userId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
      }

      const user = await User.findByIdAndUpdate(
        userId,
        updateData,
        { new: true, runValidators: true }
      );

      if (!user) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
      }

      return user;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update user');
    }
  }

  /**
 * Delete user and all associated data (cascade delete)
 */
  public async deleteUser(userId: string): Promise<void> {
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      if (!Types.ObjectId.isValid(userId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
      }

      // Get user with role to determine what to delete
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
      }

      // Delete associated profile based on role
      switch (user.role) {
        case UserRole.STUDENT:
          await StudentProfile.findOneAndDelete({ user: userId }).session(session);
          // Delete student solutions
          const studentProfile = await StudentProfile.findOne({ user: userId }).session(session);
          if (studentProfile) {
            await Solution.deleteMany({ student: studentProfile._id }).session(session);
          }
          break;
        case UserRole.COMPANY:
          await CompanyProfile.findOneAndDelete({ user: userId }).session(session);
          // Company challenges would be handled based on business requirements
          // Consider what should happen to challenges if a company is deleted
          break;
        case UserRole.ARCHITECT:
          await ArchitectProfile.findOneAndDelete({ user: userId }).session(session);
          break;
      }

      // Delete user document
      await User.findByIdAndDelete(userId).session(session);

      await session.commitTransaction();
      logger.info(`User ${userId} and all associated data successfully deleted`);
    } catch (error) {
      await session.abortTransaction();

      logger.error(
        `Error deleting user: ${error instanceof Error ? error.message : String(error)}`,
        { userId, error }
      );

      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete user');
    } finally {
      session.endSession();
    }
  }
}