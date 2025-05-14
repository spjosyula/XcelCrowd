/**
 * Challenge related types based on backend schema
 */

export enum ChallengeStatus {
  DRAFT = "draft",
  ACTIVE = "active",
  CLOSED = "closed",
  COMPLETED = "completed"
}

export enum ChallengeDifficulty {
  BEGINNER = "beginner",
  INTERMEDIATE = "intermediate",
  ADVANCED = "advanced",
  EXPERT = "expert"
}

export enum ChallengeVisibility {
  PUBLIC = "public",
  PRIVATE = "private",
  ANONYMOUS = "anonymous"
}

export interface Challenge {
  _id: string;
  title: string;
  description: string;
  company: string | { 
    _id: string;
    name: string;
    [key: string]: any; 
  }; // Company ID or full company object depending on the endpoint
  requirements: string[];
  resources?: string[];
  rewards?: string;
  deadline: string; // ISO date string
  status: ChallengeStatus;
  difficulty: ChallengeDifficulty;
  category: string[];
  maxParticipants?: number;
  currentParticipants: number;
  completedAt?: string; // ISO date string
  publishedAt?: string; // ISO date string
  tags: string[];
  claimedBy?: string; // Architect ID
  claimedAt?: string; // ISO date string
  maxApprovedSolutions?: number;
  approvedSolutionsCount: number;
  visibility: ChallengeVisibility;
  allowedInstitutions?: string[];
  isCompanyVisible: boolean;
  autoCloseOnDeadline?: boolean; // Controls whether challenge auto-closes on deadline
  createdAt: string; // ISO date string
  updatedAt: string; // ISO date string
}

export interface PaginatedChallenges {
  data: Challenge[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPrevPage: boolean;
}

export interface ChallengeFilters {
  status?: string;
  difficulty?: string;
  category?: string | string[];
  searchTerm?: string;
  page?: number;
  limit?: number;
} 