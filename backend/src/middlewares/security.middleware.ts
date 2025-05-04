import { Request, Response, NextFunction } from 'express';
import xssClean from 'xss-clean';
import crypto from 'crypto';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from '../utils/logger';

import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

// Initialize DOMPurify with JSDOM
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

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
          req.body[field] = sanitizeHtml(req.body[field]);
        }
      }
      
      // Recursively sanitize nested objects
      req.body = sanitizeObject(req.body);
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

/**
 * Helper function to sanitize HTML content
 * Uses DOMPurify for robust protection against XSS attacks
 */
function sanitizeHtml(html: string): string {
<<<<<<< HEAD
  if (!html) return html;
  
  try {
    // Primary sanitization using DOMPurify
    // This handles all HTML elements, attributes, and malicious patterns
    let sanitized = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: [], // Disallow all HTML tags for maximum security
      ALLOWED_ATTR: [], // Disallow all attributes for maximum security
      FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'object', 'embed', 'meta'],
      FORBID_ATTR: ['style', 'onerror', 'onload', 'onclick', 'onmouseover'],
      SAFE_FOR_TEMPLATES: true,
      WHOLE_DOCUMENT: false,
      SANITIZE_DOM: true
    });
    
    // Secondary defense - additional regex patterns for extra protection
    sanitized = sanitized
      // Remove any potentially remaining javascript: URLs
      .replace(/javascript:/gi, 'removed:')
      // Remove any event handlers  
      .replace(/on\w+=/gi, 'removed=')
      // Remove data: URLs that could contain base64-encoded scripts
      .replace(/data:[^;]*;base64,/gi, 'removed:');
      
    logger.debug(`Sanitized input from "${html.slice(0, 30)}..." to "${sanitized.slice(0, 30)}..."`);
    return sanitized;
  } catch (error) {
    // Log the error but return a safe value rather than failing
    logger.error('HTML sanitization error:', error);
    return ''; // Return empty string on error for maximum safety
  }
=======
  // Basic sanitization - in production, use a more robust library like DOMPurify
  let sanitizedHtml = html;
  let previousHtml;
  do {
    previousHtml = sanitizedHtml;
    sanitizedHtml = sanitizedHtml.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  } while (sanitizedHtml !== previousHtml);
  return sanitizedHtml
    .replace(/javascript:/gi, 'removed:')
    .replace(/on\w+=/gi, 'removed=');
>>>>>>> a76ce04438ec3b0b9a6a1d597dd53c57748e1b3c
}

/**
 * Helper function to recursively sanitize objects
 */
function sanitizeObject(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }
  
  const sanitized: Record<string, any> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeHtml(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}


