import mongoose, { Document, Types } from 'mongoose';

/**
 * Base interface for timestamp fields
 */
export interface ITimestamps {
  createdAt: Date;  // Records when the document was created
  updatedAt: Date;  // Records the last time the document was updated
}

/**
 * User roles enum
 */
export enum UserRole {
  STUDENT = 'student',  // Role for students who can participate in challenges
  COMPANY = 'company',  // Role for companies that can create challenges
  ARCHITECT = 'architect',  // Role for architects who can review solutions
  ADMIN = 'admin'  // Role for system administrators with full access
}

/**
 * Base User interface - core authentication fields only
 */
export interface IUser {
  _id: Types.ObjectId;  // MongoDB unique identifier for the user
  email: string;  // User's email address, used for login and communications
  password: string;  // Hashed password for user authentication
  role: UserRole;  // User's role in the system
  isEmailVerified: boolean;  // Indicates if the user's email has been verified
  emailVerificationToken?: string;  // Token sent to user for email verification
  emailVerificationTokenExpires?: Date;  // Expiration timestamp for the email verification token
  passwordResetToken?: string;  // Token sent to user for password reset
  passwordResetTokenExpires?: Date;  // Expiration timestamp for the password reset token
  comparePassword(candidatePassword: string): Promise<boolean>;  // Method to verify password during login
}

/**
 * Student user interface
 */
export interface IStudent extends IUser {
  role: UserRole.STUDENT;
}

/**
 * Company user interface
 */
export interface ICompany extends IUser {
  role: UserRole.COMPANY;
}

/**
 * Architect user interface
 */
export interface IArchitect extends IUser {
  role: UserRole.ARCHITECT;
  firstName: string;
  lastName: string;
}

/**
 * Admin user interface
 */
export interface IAdmin extends IUser {
  role: UserRole.ADMIN;
  firstName?: string;
  lastName?: string;
}

/**
 * Student profile interface
 */
export interface IStudentProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;  // Reference to the user account this profile belongs to
  firstName: string;  // Student's first name
  lastName: string;  // Student's last name
  university?: string;  // Educational institution the student belongs to
  resumeUrl?: string;  // Link to the student's uploaded resume
  bio?: string;  // Student's personal description or introduction
  profilePicture?: string;  // URL to the student's profile image
  skills: string[];  // List of technical skills the student possesses
  interests: string[];  // List of topics or areas the student is interested in
  followers: Types.ObjectId[] | IUser[];  // List of users following this student
  following: Types.ObjectId[] | IUser[];  // List of users this student is following
}

/**
 * Company profile interface
 */
export interface ICompanyProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;  // Reference to the user account this company profile belongs to
  companyName: string;  // Official name of the company
  website?: string;  // Company's official website URL
  contactNumber?: string;  // Phone number or other contact information
  industry: string;  // Industry sector the company operates in
  description?: string;  // Company description, mission statement, or about information
  address?: string;  // Physical address or location of the company
}

/**
 * Architect profile interface
 */
export interface IArchitectProfile extends Document, ITimestamps {
  user: Types.ObjectId | IUser;  // Reference to the user account this architect profile belongs to
  firstName?: string;  // Architect's first name
  lastName?: string;  // Architect's last name
  specialization?: string;  // Architect's area of technical expertise
  yearsOfExperience?: number;  // Number of years of professional experience
  bio?: string;  // Personal description or professional summary
  profilePicture?: string;  // URL to the architect's profile image
  skills: string[];  // List of technical skills and competencies
  certifications: string[];  // List of professional certifications held by the architect
}

/**
 * Challenge status enum
 */
export enum ChallengeStatus {
  DRAFT = 'draft',  // Challenge is being created but not yet published
  ACTIVE = 'active',  // Challenge is published and accepting submissions
  CLOSED = 'closed',  // Challenge is no longer accepting new submissions
  COMPLETED = 'completed',  // Challenge has been reviewed and finalized
}

/**
 * Challenge visibility enum
 */
export enum ChallengeVisibility {
  PUBLIC = 'public',     // Challenge visible to all students
  PRIVATE = 'private',   // Challenge visible only to selected colleges/institutions
  ANONYMOUS = 'anonymous' // Company identity hidden, but challenge publicly visible
}

/**
 * Challenge difficulty enum
 */
export enum ChallengeDifficulty {
  BEGINNER = 'beginner',  // Entry-level difficulty, suitable for newcomers
  INTERMEDIATE = 'intermediate',  // Medium difficulty requiring some experience
  ADVANCED = 'advanced',  // High difficulty requiring significant experience
  EXPERT = 'expert'  // Highest difficulty level for specialists
}

/**
 * Challenge interface
 */
export interface IChallenge extends Document, ITimestamps {
  title: string;  // Name or title of the challenge
  description: string;  // Detailed description of the challenge
  company: Types.ObjectId | ICompanyProfile;  // Company that created the challenge
  requirements: string[];  // List of specific requirements for solutions
  resources?: string[];  // Optional resources provided to help with the challenge (need to allow file uploads)
  rewards?: string;  // Incentives or rewards offered for successful solutions
  deadline: Date;  // Due date for submitting solutions
  status: ChallengeStatus;  // Current status of the challenge
  difficulty: ChallengeDifficulty;  // Difficulty level of the challenge
  category: string[];  // Categories or domains the challenge belongs to
  maxParticipants?: number;  // Maximum allowed number of participants
  currentParticipants: number;  // Current count of participants
  completedAt?: Date;  // Date when the challenge was completed
  publishedAt?: Date;  // Date when the challenge was published
  tags: string[];  // Keywords or tags associated with the challenge
  claimedBy?: mongoose.Types.ObjectId; // Architect who has claimed the challenge for review
  claimedAt?: Date; // Date when the challenge was claimed
  maxApprovedSolutions?: number;  // Maximum number of solutions that can be approved
  approvedSolutionsCount: number;  // Current count of approved solutions
  visibility: ChallengeVisibility;  // Controls who can see the challenge
  allowedInstitutions?: string[];   // List of institutions that can see private challenges
  isCompanyVisible: boolean;        // Whether company identity is shown (false for anonymous)
  autoCloseOnDeadline?: boolean;    // Controls whether the challenge should be automatically closed when deadline is reached
  
  // Methods
  isDeadlinePassed(): boolean;  // Checks if the challenge deadline has passed
  isApprovalLimitReached(): boolean;  // Checks if the maximum number of approvals has been reached
}

/**
 * Solution status enum
 */
export enum SolutionStatus {
  DRAFT = 'draft',  // Solution is being created but not yet submitted
  SUBMITTED = 'submitted',  // Initial state when solution is first submitted
  CLAIMED = 'claimed',  // Solution has been claimed for review by an architect
  UNDER_REVIEW = 'under_review',  // Solution is being reviewed by architects (including AI evaluated solutions)
  APPROVED = 'approved',  // Solution has been approved by reviewers
  REJECTED = 'rejected',  // Solution has been rejected by reviewers
  SELECTED = 'selected'  // Solution has been selected as one of the best
}

/**
 * Solution interface
 */
export interface ISolution extends Document, ITimestamps {
  challenge: Types.ObjectId | IChallenge;  // Reference to the challenge this solution is for
  student: Types.ObjectId | IStudentProfile;  // Student who submitted the solution
  title: string;  // Title of the solution
  description: string;  // Explanation of the approach or implementation
  submissionUrl: string;  // Link to the actual solution files or repository
  status: SolutionStatus;  // Current status of the solution in the review workflow
  feedback?: string;  // Comments or suggestions from reviewers
  reviewedBy?: Types.ObjectId | IArchitectProfile;  // Architect who reviewed this solution
  reviewedAt?: Date;  // When the solution was reviewed
  score?: number;  // Numerical assessment of the solution quality (from architect review)
  
  // AI evaluation related fields
  aiScore?: number;  // Score assigned by AI evaluation (0-100)
  evaluationScores?: Map<string, number>;  // Scores from different evaluation components
  reviewPriority?: 'low' | 'medium' | 'high';  // Priority for architect review
  rejectionReason?: string;  // Reason for rejection if status is REJECTED
  notes?: string;  // Notes from architects or AI system
  lastUpdatedAt?: Date;  // When the solution was last updated
  
  tags?: string[];  // Keywords or tags associated with the solution
  submittedAt?: Date;  // When the solution was submitted
  selectedAt?: Date;  // When the solution was selected as exemplary
  selectedBy?: Types.ObjectId | ICompanyProfile;  // Company who selected this solution
  companyFeedback?: string;  // Feedback from company to the student when selected as winner
  selectionReason?: string;  // Reason why the company selected this solution
  
  // Internal runtime context for evaluation pipeline data sharing between agents
  context?: {
    evaluationId?: string;
    challengeContext?: any;  // Context about the challenge for AI agents
    currentStage?: string;  // Current stage in the evaluation pipeline
    previousResults?: Record<string, any>;  // Results from previous pipeline stages
    pipelineResults?: {
      [key: string]: any;  // Allow for dynamic agent names
      SpamFilteringAgent?: any;
      RequirementsComplianceAgent?: any;
      CodeQualityAgent?: any;
      ScoringFeedbackAgent?: any;
    };
    [key: string]: any;  // Allow for other context data
  };
}


export * from './ai-agent';
export * from './ai-agent-shared';

/**
 * Company solution selection response interface
 */
export interface ICompanySelectionResponse {
  solutionId: string;  // ID of the selected solution
  feedback?: string;   // Optional feedback from company to the student
  selectionReason?: string; // Optional reason for selection
  companyId: string;   // ID of the company making the selection
  challengeId: string; // ID of the challenge
}