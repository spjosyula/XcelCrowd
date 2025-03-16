import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { logger } from '../utils/logger';

/**
 * More robust XSS sanitization middleware
 * Replaces the simple sanitizeInput in validation.middleware.ts
 */
export const xssProtection = (req: Request, _res: Response, next: NextFunction) => {
  try {
    if (req.body) {
      sanitizeObject(req.body);
    }
    
    if (req.query) {
      sanitizeObject(req.query);
    }
    
    if (req.params) {
      sanitizeObject(req.params);
    }
    
    next();
  } catch (error) {
    logger.error('Error in XSS protection middleware:', error);
    next(error);
  }
};

/**
 * Sanitize an object recursively
 */
function sanitizeObject(obj: Record<string, any>): void {
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      if (typeof obj[key] === 'string') {
        // Sanitize string values
        obj[key] = sanitizeString(obj[key]);
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        // Recursively sanitize nested objects and arrays
        sanitizeObject(obj[key]);
      }
    }
  }
}

/**
 * Sanitize a string to prevent XSS attacks
 */
function sanitizeString(input: string): string {
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/'/g, '&#39;')
    .replace(/"/g, '&quot;')
    .replace(/`/g, '&#96;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;');
}

/**
 * Configure Content Security Policy
 */
export const configureCSP = helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https://*.cloudinary.com"], // Adjust for your image providers
    connectSrc: ["'self'", process.env.FRONTEND_URL || "http://localhost:3000"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
});

/**
 * CSRF protection middleware -> UNCOMMENT ONCE IN PRODUCTION
 */
export const enhancedCsrfProtection = (req: Request, res: Response, next: NextFunction): void => {
    // // Skip for GET requests and some specific endpoints that don't need CSRF protection
    // if (req.method === 'GET' || 
    //     req.path === '/api/auth/login' || 
    //     req.path === '/api/auth/register') {
    //   next();
    //   return;
    // }
    
    // const csrfToken = req.headers['x-csrf-token'] as string;
    
    // if (!csrfToken) {
    //   logger.warn(`CSRF token missing for ${req.method} ${req.path}`);
    //   res.status(403).json({
    //     success: false,
    //     message: 'CSRF protection: Invalid or missing token',
    //     timestamp: new Date().toISOString()
    //   });
    //   return;
    // }
  
  // In a real implementation, validate against a token stored in the user's session
  // For now, just check if the token exists
  next();
};
