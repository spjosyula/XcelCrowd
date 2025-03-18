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
  firstName?: string; // Added for student and architect
  lastName?: string; // Added for student and architect
  companyName?: string; // Added for company
  isEmailVerified: boolean; // Flag to track email verification status
  emailVerificationToken?: string; // Token for email verification
  emailVerificationTokenExpires?: Date; // Expiration for email verification token
  passwordResetToken?: string; // Token for password reset
  passwordResetTokenExpires?: Date; // Expiration for password reset token
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

/**
 * Architect profile interface
 */
export interface IArchitectProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;
  firstName?: string;
  lastName?: string;
  specialization?: string;
  yearsOfExperience?: number;
  bio?: string;
  profilePicture?: string;
  skills: string[];
  certifications: string[];
}

/**
 * Challenge status enum
 */
export enum ChallengeStatus {
  DRAFT = 'draft', //Challenge is being created
  ACTIVE = 'active', //Challenge is published and open for submissions
  CLOSED = 'closed', //Challenge is closed and no longer accepting submissions
  COMPLETED = 'completed', //Challenge has been reviewed and completed
}

/**
 * Challenge difficulty enum
 */
export enum ChallengeDifficulty {
  BEGINNER = 'beginner',
  INTERMEDIATE = 'intermediate',
  ADVANCED = 'advanced',
  EXPERT = 'expert'
}

/**
 * Challenge interface
 */
export interface IChallenge extends Document, ITimestamps {
  title: string;
  description: string;
  company: Types.ObjectId | ICompanyProfile;
  requirements: string[];
  resources?: string[];
  rewards?: string;
  deadline?: Date;
  status: ChallengeStatus;
  difficulty: ChallengeDifficulty;
  category: string[];
  maxParticipants?: number;
  currentParticipants: number;
  tags: string[];
  // Added properties for enhanced workflow
  maxApprovedSolutions?: number;
  approvedSolutionsCount: number;
  // Methods
  isDeadlinePassed(): boolean;
  isApprovalLimitReached(): boolean;
}

/**
 * Solution status enum
 */
export enum SolutionStatus {
  SUBMITTED = 'submitted',
  UNDER_REVIEW = 'under_review',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  SELECTED = 'selected'
}

/**
 * Solution interface
 */
export interface ISolution extends Document, ITimestamps {
  challenge: Types.ObjectId | IChallenge;
  student: Types.ObjectId | IStudentProfile;
  title: string;
  description: string;
  submissionUrl: string;
  status: SolutionStatus;
  feedback?: string;
  reviewedBy?: Types.ObjectId | IArchitectProfile;
  reviewedAt?: Date;
  score?: number;
  // Added fields for enhanced workflow
  selectedAt?: Date;
  selectedBy?: Types.ObjectId | IArchitectProfile;
}

/**
 * HTTP Status codes enum
 */
export enum HTTP_STATUS {
  OK = 200,
  CREATED = 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409,
  UNPROCESSABLE_ENTITY = 422,
  INTERNAL_SERVER_ERROR = 500
}