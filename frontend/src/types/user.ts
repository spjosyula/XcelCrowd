/**
 * User-related types based on backend schema
 */

export enum UserRole {
  ADMIN = "admin",
  STUDENT = "student",
  COMPANY = "company",
  ARCHITECT = "architect"
}

export interface User {
  userId: string;
  email: string;
  role: UserRole;
  profile?: string; // Profile ID
  name?: string;
  isEmailVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
  role: UserRole;
} 