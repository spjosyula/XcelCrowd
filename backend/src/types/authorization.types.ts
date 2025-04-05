import { UserRole } from '../models/interfaces';

/**
 * Standard authorization patterns for consistent security enforcement
 */
export enum AuthPattern {
  // Basic patterns
  PUBLIC = 'public',                // No auth required
  AUTHENTICATED = 'authenticated',  // Any logged-in user
  ADMIN_ONLY = 'admin_only',        // Only admins
  
  // Role-based patterns
  STUDENT_ONLY = 'student_only',    
  COMPANY_ONLY = 'company_only',
  ARCHITECT_ONLY = 'architect_only',
  
  // Resource ownership patterns
  SELF_ONLY = 'self_only',          // User can only access own resources
  RESOURCE_OWNER = 'resource_owner', // Owner of the related resource
  
  // Combined patterns
  SELF_OR_ADMIN = 'self_or_admin',  // Self or admin
  COMPANY_OR_ADMIN = 'company_or_admin',
  ARCHITECT_OR_ADMIN = 'architect_or_admin',
  ARCHITECT_OR_ADMIN_OR_COMPANY = "ARCHITECT_OR_ADMIN_OR_COMPANY",
}

/**
 * Maps authorization patterns to allowed roles
 */
export const authPatternRoles: Record<AuthPattern, UserRole[] | null> = {
  [AuthPattern.PUBLIC]: null, // null means no auth required
  [AuthPattern.AUTHENTICATED]: [UserRole.STUDENT, UserRole.COMPANY, UserRole.ARCHITECT, UserRole.ADMIN],
  [AuthPattern.ADMIN_ONLY]: [UserRole.ADMIN],
  [AuthPattern.STUDENT_ONLY]: [UserRole.STUDENT],
  [AuthPattern.COMPANY_ONLY]: [UserRole.COMPANY],
  [AuthPattern.ARCHITECT_ONLY]: [UserRole.ARCHITECT],
  [AuthPattern.SELF_ONLY]: [UserRole.STUDENT, UserRole.COMPANY, UserRole.ARCHITECT, UserRole.ADMIN], // Role check handled separately
  [AuthPattern.RESOURCE_OWNER]: [UserRole.STUDENT, UserRole.COMPANY, UserRole.ARCHITECT, UserRole.ADMIN], // Ownership check handled separately
  [AuthPattern.SELF_OR_ADMIN]: [UserRole.ADMIN], // Self check handled separately
  [AuthPattern.COMPANY_OR_ADMIN]: [UserRole.COMPANY, UserRole.ADMIN],
  [AuthPattern.ARCHITECT_OR_ADMIN]: [UserRole.ARCHITECT, UserRole.ADMIN],
  [AuthPattern.ARCHITECT_OR_ADMIN_OR_COMPANY]: [UserRole.ARCHITECT, UserRole.ADMIN, UserRole.COMPANY],
}