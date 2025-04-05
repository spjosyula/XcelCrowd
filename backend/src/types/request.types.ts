import { Request } from 'express';
import { UserRole } from '../models/interfaces';

/**
 * Extended Request interface with authenticated user data
 */
export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role: UserRole | string; // Allow both string and enum for compatibility
    profile?: string; // Remove ObjectId type since it's not compatible with the base Request
  } & Record<string, any>; // Allow additional properties
  
  /**
   * Validated data from request validation middleware
   * Set by the validation middleware after successful schema validation
   */
  validatedData?: Record<string, any>;
}

/**
 * Type guard to check if a request is authenticated
 * @param req - The request to check
 * @returns Boolean indicating if the request has a user object
 */
export function isAuthenticated(req: AuthRequest): boolean {
  return req.user !== undefined;
}

/**
 * Type guard to check if user has a specific role
 * @param req - The authenticated request
 * @param roles - Array of allowed roles
 * @returns Boolean indicating if the user has one of the allowed roles
 */
export function hasRole(req: AuthRequest, roles: UserRole[]): boolean {
  return req.user !== undefined && 
    roles.includes(req.user.role as UserRole);
}

/**
 * Helper to safely get the role as enum
 * @param req - The authenticated request
 * @returns The role as UserRole enum or undefined
 */
export function getUserRole(req: AuthRequest): UserRole | undefined {
  if (!req.user?.role) return undefined;
  return req.user.role as UserRole;
}