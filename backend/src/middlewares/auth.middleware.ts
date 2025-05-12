import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { UserRole } from '../models';
import rateLimit from 'express-rate-limit';
import { Types } from 'mongoose';
import { AuthPattern, authPatternRoles } from '../types/authorization.types';
import { routeConfig } from '../config/routes.config';

// Define interface for decoded JWT token
interface DecodedToken {
  userId: string;
  email: string;
  role: string;
  profile?: string; 
  iat: number;
  exp: number;
  jti?: string; // JWT ID for revocation tracking
  tokenVersion?: number; // Version number for handling revocation
}

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: string;
        profile?: string;
        tokenId?: string; // JWT ID
        tokenVersion?: number; // Token version
      };
    }
  }
}

// In-memory token blacklist (for development/testing)
// In production, this should be replaced with a distributed cache like Redis
const TOKEN_BLACKLIST = new Set<string>();

// Track user token versions in-memory (for development/testing)
// In production, this should be stored in the User model in the database
const USER_TOKEN_VERSIONS = new Map<string, number>();

/**
 * Rate limiter to prevent brute force attacks
 */
export const loginRateLimiter = rateLimit({
  // windowMs: 15 * 60 * 1000, // 15 minutes
  // max: 5, // 5 requests per window per IP
  // standardHeaders: true,
  // legacyHeaders: false,
  // message: { 
  //   status: 'error', 
  //   message: 'Too many login attempts, please try again after 15 minutes' 
  // }
});

/**
 * Authentication middleware to protect routes
 */
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // 1) Get token from authorization header or cookies
    let token: string | undefined;
    
    // First check cookies
    if (req.cookies && req.cookies.jwt) {
      token = req.cookies.jwt;
    }
    // If not in cookies, check authorization header
    else {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
      }
    }
    
    if (!token) {
      return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication required'));
    }
    
    // 2) Validate token
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET is not defined in environment variables');
      return next(new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Authentication service configuration error'));
    }
    
    try {
      // Convert string secret to Buffer to avoid type issues
      const secretBuffer = Buffer.from(jwtSecret, 'utf-8');
      
      const decoded = jwt.verify(token, secretBuffer, {
        algorithms: ['HS256'] // Explicitly specify algorithm
      }) as DecodedToken;
      
      // 3) Check if token is expired
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded.exp < currentTime) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Your session has expired. Please log in again'));
      }
      
      // 4) Check if specific token has been blacklisted
      if (decoded.jti && TOKEN_BLACKLIST.has(decoded.jti)) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'This session has been revoked. Please log in again'));
      }
      
      // 5) Check token version (for password changes/force logout)
      if (decoded.tokenVersion !== undefined && decoded.userId) {
        const currentVersion = USER_TOKEN_VERSIONS.get(decoded.userId) || 0;
        if (decoded.tokenVersion < currentVersion) {
          return next(new ApiError(
            HTTP_STATUS.UNAUTHORIZED, 
            'Your credentials have changed. Please log in again'
          ));
        }
      }
      
      // 6) Attach user to request
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role
      };
      
      // Add profile if it exists in the token
      if ('profile' in decoded && decoded.profile) {
        req.user.profile = decoded.profile;
      }
      
      // Add token ID if it exists for revocation tracking
      if (decoded.jti) {
        req.user.tokenId = decoded.jti;
      }
      
      // Add token version if it exists
      if (decoded.tokenVersion !== undefined) {
        req.user.tokenVersion = decoded.tokenVersion;
      }
      
      // 7) Log successful authentication
      logger.debug(`User ${decoded.email} authenticated successfully`);
      
      next();
    } catch (error) {
      // Handle different JWT errors
      if (error instanceof jwt.JsonWebTokenError) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid token. Please log in again'));
      }
      
      if (error instanceof jwt.TokenExpiredError) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Your token has expired. Please log in again'));
      }
      
      if (error instanceof jwt.NotBeforeError) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Token not yet active'));
      }
      
      return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication failed'));
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Authorization middleware based on user roles
 */
export const authorize = (roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication required'));
    }
    
    if (!roles.includes(req.user.role as UserRole)) {
      logger.warn(`Unauthorized access attempt: User ${req.user.email} (${req.user.role}) attempted to access resource restricted to ${roles.join(', ')}`);
      return next(
        new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to perform this action'
        )
      );
    }
    
    next();
  };
};

/**
 * Platform-wide authentication middleware
 * Applies authentication to all routes except public ones
 */
export const authenticatedUsersOnly = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip authentication for public paths
    if (routeConfig.isPublicPath(req.path)) {
      return next();
    }
    
    // For all other paths, require authentication
    if (!req.user) {
      logger.warn(`Unauthenticated access attempt to restricted resource: ${req.path}`);
      return next(new ApiError(
        HTTP_STATUS.UNAUTHORIZED, 
        'Authentication required. This platform is only accessible to registered users.'
      ));
    }
    
    // User is authenticated, proceed
    next();
  };
};

/**
 * Conditional authentication middleware
 * Only applies authentication if the route is not public
 */
export const conditionalAuthenticate = (req: Request, res: Response, next: NextFunction) => {
  // Skip authentication for public paths
  if (routeConfig.isPublicPath(req.path)) {
    return next();
  }
  
  // Apply authentication for protected paths
  authenticate(req, res, next);
};

/**
 * Authorization middleware based on predefined patterns
 * Uses the AuthPattern enum to apply consistent access control across the application
 * 
 * @param pattern - The authorization pattern to apply
 * @returns Express middleware function that handles the authorization
 */
export const authorizePattern = (pattern: AuthPattern) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // If pattern is PUBLIC, allow access without authentication
    if (pattern === AuthPattern.PUBLIC) {
      return next();
    }
    
    // Check if user is authenticated
    if (!req.user) {
      return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication required'));
    }
    
    // Get the roles allowed for this pattern
    const allowedRoles = authPatternRoles[pattern];
    
    // If no roles defined (shouldn't happen with correct enum usage)
    if (!allowedRoles) {
      logger.error(`Invalid authorization pattern: ${pattern}`);
      return next(new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Authorization configuration error'));
    }
    
    // For self-only patterns, perform additional checks
    if (pattern === AuthPattern.SELF_ONLY) {
      const userId = req.params.userId || req.body.userId;
      if (userId && userId !== req.user.userId) {
        return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'You can only access your own resources'));
      }
      return next();
    }
    
    // For self-or-admin patterns
    if (pattern === AuthPattern.SELF_OR_ADMIN) {
      const userId = req.params.userId || req.body.userId;
      if (req.user.role === UserRole.ADMIN || (userId && userId === req.user.userId)) {
        return next();
      }
      return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'You do not have permission to perform this action'));
    }
    
    // Standard role-based authorization
    if (!allowedRoles.includes(req.user.role as UserRole)) {
      logger.warn(`Unauthorized access attempt: User ${req.user.email} (${req.user.role}) attempted to access resource restricted to ${allowedRoles.join(', ')}`);
      return next(
        new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to perform this action'
        )
      );
    }
    
    // If we get here, the user is authorized
    next();
  };
};

/**
 * Institution-based authorization middleware for private challenges
 * 
 * This middleware checks if a student from a particular institution 
 * is allowed to access a private challenge based on the challenge's allowedInstitutions.
 * 
 * @param challengeParam - The parameter name in the request that contains the challenge ID (default: 'id')
 * @returns Express middleware function that handles the authorization
 */
export const authorizeInstitutionForChallenge = (challengeParam: string = 'id') => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Skip for non-student users (companies, architects, admins)
      if (req.user?.role !== UserRole.STUDENT) {
        return next();
      }
      
      const challengeId = req.params[challengeParam];
      
      if (!challengeId || !Types.ObjectId.isValid(challengeId)) {
        return next(new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid challenge ID'));
      }
      
      // Import models here to avoid circular dependencies
      const { default: Challenge } = await import('../models/Challenge');
      const { default: StudentProfile } = await import('../models/StudentProfile');
      
      // Retrieve the challenge
      const challenge = await Challenge.findById(challengeId);
      
      if (!challenge) {
        return next(new ApiError(HTTP_STATUS.NOT_FOUND, 'Challenge not found'));
      }
      
      // If challenge is not private, no institution check needed
      if (challenge.visibility !== 'private') {
        return next();
      }
      
      // For private challenges, verify student's institution access
      if (!req.user?.userId) {
        return next(new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Authentication required'));
      }
      
      // Get student profile to check university
      const studentProfile = await StudentProfile.findOne({ user: req.user.userId });
      if (!studentProfile) {
        return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'Student profile not found'));
      }
      
      const studentUniversity = studentProfile.university;
      
      // Verify institution access
      if (!studentUniversity || !challenge.allowedInstitutions?.includes(studentUniversity)) {
        logger.warn(`Institution access denied: User ${req.user.email} from ${studentUniversity || 'unknown'} institution attempted to access challenge restricted to ${challenge.allowedInstitutions?.join(', ')}`);
        return next(new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to access this challenge'
        ));
      }
      
      // Institution access granted
      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * CSRF protection middleware
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  // const csrfToken = req.headers['x-csrf-token'] as string;
  
  // // In a real implementation, validate against a token stored in the user's session
  // if (!csrfToken) {
  //   return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'CSRF token missing'));
  // }
  
  // // Continue if token exists (implement actual validation in production)
  next();
};