import { Request, Response, NextFunction } from 'express';
import xssClean from 'xss-clean';
import crypto from 'crypto';
import { MongoSanitizer } from '../utils/mongo.sanitize';


/**
 * XSS protection middleware
 */
export const xssProtection = (req: Request, res: Response, next: NextFunction) => {
  // Apply xss-clean middleware
  xssClean()(req, res, (err: Error | null) => {
    if (err) return next(err);
    
    // Additional custom XSS protection for specific fields
    if (req.body) {
      // Sanitize common fields that might contain HTML
      const fieldsToSanitize = ['description', 'content', 'message', 'text', 'html', 'comment'];
      
      for (const field of fieldsToSanitize) {
        if (req.body[field] && typeof req.body[field] === 'string') {
          req.body[field] = MongoSanitizer.sanitizeHtml(req.body[field]);
        }
      }
      
      // Recursively sanitize nested objects
      req.body = MongoSanitizer.sanitizeObjectId(req.body);
    }
    
    next();
  });
};

/**
 * Configure Content Security Policy
 */
export const configureCSP = (req: Request, res: Response, next: NextFunction) => {
  // Generate nonce for inline scripts if needed
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  
  // Set CSP header
  // res.setHeader('Content-Security-Policy', `
  //   default-src 'self';
  //   script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net https://unpkg.com;
  //   style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;
  //   img-src 'self' data: https://res.cloudinary.com;
  //   font-src 'self' https://fonts.gstatic.com;
  //   connect-src 'self' https://api.cloudinary.com;
  //   frame-src 'none';
  //   object-src 'none';
  //   base-uri 'self';
  //   form-action 'self';
  //   frame-ancestors 'none';
  //   block-all-mixed-content;
  //   upgrade-insecure-requests;
  // `.replace(/\s+/g, ' ').trim());
  
  next();
};

/**
 * Enhanced CSRF protection middleware - UNCOMMENT IN PRODUCTION, COMMENTED FOR EASIER TESTING
 */
export const enhancedCsrfProtection = (req: Request, res: Response, next: NextFunction) => {
  // // Skip for GET, HEAD, OPTIONS requests
  // if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
  //   return next();
  // }
  
  // // Skip for specific endpoints that don't need CSRF protection
  // const skipPaths = ['/api/auth/login', '/api/auth/register'];
  // if (skipPaths.some(path => req.path.includes(path))) {
  //   return next();
  // }
  
  // const csrfToken = req.headers['x-csrf-token'] as string;
  
  // // In a real implementation, validate against a token stored in the user's session
  // // For now, we're just checking if the token exists
  // if (!csrfToken) {
  //   logger.warn(`CSRF token missing for ${req.method} ${req.path}`);
  //   return next(new ApiError(HTTP_STATUS.FORBIDDEN, 'CSRF token missing'));
  // }
  
  // // Continue if token exists (implement actual validation in production)
  next();
};


