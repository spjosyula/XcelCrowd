import { Types, Document } from 'mongoose';
import { User, IUser, UserRole } from '../models';
import { ApiError } from '../utils/ApiError';
import { HTTP_STATUS } from '../constants';

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
   * Delete user
   */
  public async deleteUser(userId: string): Promise<void> {
    try {
      if (!Types.ObjectId.isValid(userId)) {
        throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
      }
      
      const result = await User.findByIdAndDelete(userId);
      if (!result) {
        throw new ApiError(HTTP_STATUS.NOT_FOUND, 'User not found');
      }
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete user');
    }
  }
}