import { Document, Types } from 'mongoose';

/**
 * Base interface for timestamp fields
 */
export interface ITimestamps {
  createdAt: Date;
  updatedAt: Date;
}

/**
 * User roles enum
 */
export enum UserRole {
  STUDENT = 'student',
  COMPANY = 'company',
  ARCHITECT = 'architect',
  ADMIN = 'admin'
}

/**
 * Base User interface
 */
export interface IUser {
  _id: Types.ObjectId; // Add explicit _id property
  email: string;
  password: string;
  role: UserRole;
  comparePassword(candidatePassword: string): Promise<boolean>; // Add the method signature
}

/**
 * Student profile interface
 */
export interface IStudentProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;
  firstName?: string;
  lastName?: string;
  university?: string;
  resumeUrl?: string;
  bio?: string;
  profilePicture?: string;
  skills: string[];
  interests: string[];
  followers: Types.ObjectId[] | IUser[];
  following: Types.ObjectId[] | IUser[];
}

/**
 * Company profile interface
 */
export interface ICompanyProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;
  companyName?: string;
  website?: string;
  contactNumber?: string;
  industry?: string;
  description?: string;
  address?: string;
}