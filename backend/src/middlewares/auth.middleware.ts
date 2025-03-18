import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/ApiError';
import { logger } from '../utils/logger';
import { UserRole } from '../models';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { expressjwt as jwtMiddleware } from 'express-jwt';

// Define interface for decoded JWT token
interface DecodedToken {
  userId: string;
  email: string;
  role: string;
  iat: number;
  exp: number;
}

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: string;
      };
    }
  }
}

/**
 * Rate limiter to prevent brute force attacks
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { 
    status: 'error', 
    message: 'Too many login attempts, please try again after 15 minutes' 
  }
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
    const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key-for-development';
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
      
      // 4) Attach user to request
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role
      };
      
      // 5) Log successful authentication
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
 * CSRF protection middleware
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  const csrfToken = req.headers['x-csrf-token'] as string;
  
  // In a real implementation, validate against a token stored in the user's session
  if (!csrfToken) {
    return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'CSRF token missing'));
  }
  
  // Continue if token exists (implement actual validation in production)
  next();
};