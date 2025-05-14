import { ApiError } from './api.error';
import { HTTP_STATUS } from '../constants';
import { UserRole } from '../models/interfaces';
import { AuthRequest } from '../types/request.types';
import { Types } from 'mongoose';
import { logger } from './logger';

/**
 * Types of resource ownership checks
 */
export interface OwnershipCheck {
  /** The resource to check ownership of */
  resource: any;
  /** The ID field in the resource that refers to the owner */
  resourceOwnerIdField: string;
  /** The role that owns this resource */
  ownerRole: UserRole;
  /** Optional custom message when ownership check fails */
  message?: string;
}

/**
 * Relationship check between entities
 */
export interface RelationshipCheck {
  /** Function that performs the check and returns true if authorized */
  check: (req: AuthRequest, resource: any) => boolean | Promise<boolean>;
  /** Message to display when check fails */
  message: string;
}

/**
 * Authorization service that centralizes access control logic
 */
export class AuthorizationService {
  /**
   * Verify user authentication
   */
  public static verifyAuthentication(req: AuthRequest): void {
    if (!req.user) {
      throw new ApiError(
        HTTP_STATUS.UNAUTHORIZED,
        'Authentication required',
        true,
        'UNAUTHENTICATED'
      );
    }
  }

  /**
   * Verify user has one of the allowed roles
   */
  public static verifyRole(req: AuthRequest, allowedRoles: UserRole[]): void {
    this.verifyAuthentication(req);

    if (!allowedRoles || allowedRoles.length === 0) {
      return; // No role restrictions
    }

    const userRole = req.user!.role as UserRole;
    if (!allowedRoles.includes(userRole)) {
      logger.warn(`Role authorization failed: User ${req.user!.userId} with role ${userRole} attempted to access resource restricted to ${allowedRoles.join(', ')}`);
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        'You do not have permission to perform this action',
        true,
        'FORBIDDEN_ROLE'
      );
    }
  }

  /**
 * Get the profile ID for a user with a specific role
 * Dynamic approach that obtains profile ID from token or database as needed
 */
  public static async getUserProfileId(req: AuthRequest, role: UserRole): Promise<string> {
    this.verifyAuthentication(req);

    if (req.user!.role !== role) {
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        `This action requires ${role} role`,
        true,
        'WRONG_ROLE'
      );
    }

    // First check if profile ID is in token
    if (req.user!.profile) {
      return req.user!.profile.toString();
    }

    // If not in token, fetch from database based on role
    try {
      let profileId: string | null = null;

      if (role === UserRole.COMPANY) {
        const { default: CompanyProfile } = await import('../models/CompanyProfile');
        const profile = await CompanyProfile.findOne({ user: req.user!.userId }).lean();
        if (profile && profile._id) {
          profileId = profile._id.toString();
          logger.debug('[getUserProfileId] Found company profile', { 
            userId: req.user!.userId, 
            profileId 
          });
        }
      }
      else if (role === UserRole.STUDENT) {
        const { default: StudentProfile } = await import('../models/StudentProfile');
        const profile = await StudentProfile.findOne({ user: req.user!.userId }).lean();
        if (profile && profile._id) {
          profileId = profile._id.toString();
          logger.debug('[getUserProfileId] Found student profile', { 
            userId: req.user!.userId, 
            profileId 
          });
        }
      }
      else if (role === UserRole.ARCHITECT) {
        const { default: ArchitectProfile } = await import('../models/ArchitectProfile');
        const profile = await ArchitectProfile.findOne({ user: req.user!.userId }).lean();
        if (profile && profile._id) {
          profileId = profile._id.toString();
          logger.debug('[getUserProfileId] Found architect profile', { 
            userId: req.user!.userId, 
            profileId 
          });
        }
      }

      if (!profileId) {
        logger.warn(`[getUserProfileId] Profile not found for user ${req.user!.userId} with role ${role}`);
        throw new ApiError(HTTP_STATUS.FORBIDDEN, 'Profile not found', true, 'PROFILE_NOT_FOUND');
      }

      // Cache the profile ID in the request for future use
      req.user!.profile = profileId;

      return profileId;
    } catch (error) {
      logger.error(`[getUserProfileId] Error retrieving profile for user ${req.user!.userId} with role ${role}: ${error instanceof Error ? error.message : String(error)}`);
      if (error instanceof ApiError) throw error;
      throw new ApiError(HTTP_STATUS.FORBIDDEN, 'Profile not found', true, 'PROFILE_NOT_FOUND');
    }
  }

  /**
   * Verify that a user owns a resource
   */
  public static async verifyOwnership(req: AuthRequest, ownershipCheck: OwnershipCheck): Promise<void> {
    this.verifyAuthentication(req);

    const { resource, resourceOwnerIdField, ownerRole, message } = ownershipCheck;

    if (!resource) {
      throw new ApiError(
        HTTP_STATUS.NOT_FOUND,
        'Resource not found',
        true,
        'RESOURCE_NOT_FOUND'
      );
    }

    // Admin always passes ownership checks
    if (req.user!.role === UserRole.ADMIN) {
      return;
    }

    // Check if user has the role required to own this resource
    if (req.user!.role !== ownerRole) {
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        message || 'You do not have permission to access this resource',
        true,
        'FORBIDDEN_ROLE'
      );
    }

    // Get the profile ID for the user
    const profileId = await this.getUserProfileId(req, ownerRole);

    // Get the owner ID from the resource
    let resourceOwnerId: string;
    if (typeof resource[resourceOwnerIdField] === 'string') {
      resourceOwnerId = resource[resourceOwnerIdField];
    } else if (resource[resourceOwnerIdField] instanceof Types.ObjectId) {
      resourceOwnerId = resource[resourceOwnerIdField].toString();
    } else if (typeof resource[resourceOwnerIdField] === 'object' && resource[resourceOwnerIdField]?._id) {
      // Handle populated fields
      resourceOwnerId = resource[resourceOwnerIdField]._id.toString();
    } else {
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Invalid resource owner ID field',
        true,
        'INVALID_OWNER_ID'
      );
    }

    // Compare the user's profile ID with the resource owner ID
    if (profileId !== resourceOwnerId) {
      logger.warn(`Ownership check failed: User ${req.user!.userId} with profile ${profileId} attempted to access resource owned by ${resourceOwnerId}`);
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        message || 'You do not have permission to access this resource',
        true,
        'FORBIDDEN_OWNERSHIP'
      );
    }
  }

  /**
   * Verify a relationship between user and resource
   */
  public static async verifyRelationship(
    req: AuthRequest,
    resource: any,
    relationshipCheck: RelationshipCheck
  ): Promise<void> {
    this.verifyAuthentication(req);

    if (!resource) {
      throw new ApiError(
        HTTP_STATUS.NOT_FOUND,
        'Resource not found',
        true,
        'RESOURCE_NOT_FOUND'
      );
    }

    // Admin always passes relationship checks
    if (req.user!.role === UserRole.ADMIN) {
      return;
    }

    // Execute the check function
    const isAuthorized = await relationshipCheck.check(req, resource);

    if (!isAuthorized) {
      logger.warn(`Relationship check failed: User ${req.user!.userId} failed custom relationship check`);
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        relationshipCheck.message,
        true,
        'FORBIDDEN_RELATIONSHIP'
      );
    }
  }

  /**
   * Comprehensive authorization check that combines multiple checks
   */
  public static async authorize(
    req: AuthRequest,
    options: {
      allowedRoles?: UserRole[];
      ownershipCheck?: OwnershipCheck;
      relationshipCheck?: RelationshipCheck;
    }
  ): Promise<void> {
    this.verifyAuthentication(req);

    const { allowedRoles, ownershipCheck, relationshipCheck } = options;

    // Check roles if specified
    if (allowedRoles && allowedRoles.length > 0) {
      this.verifyRole(req, allowedRoles);
    }

    // Check ownership if specified
    if (ownershipCheck) {
      this.verifyOwnership(req, ownershipCheck);
    }

    // Check relationship if specified
    if (relationshipCheck) {
      await this.verifyRelationship(req, ownershipCheck?.resource || relationshipCheck.check, relationshipCheck);
    }
  }
}