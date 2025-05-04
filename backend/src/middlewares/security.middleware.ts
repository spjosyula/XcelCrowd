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
      SANITIZE_DOM: true,
      ADD_URI_SAFE_ATTR: ['href', 'src'], // Apply URL sanitization to these attributes
    });
    
    // Secondary defense - comprehensive URL scheme sanitization
    sanitized = sanitized
      // Block all potentially executable URL schemes
      .replace(/(?:javascript|data|vbscript|blob|mhtml|ms-appx|ms-appdata|ms-excel|ms-powerpoint|ms-visio|ms-word|ms-access):/gi, 'unsafe:')
      // Block all event handlers
      .replace(/\bon\w+\s*=/gi, 'data-blocked=')
      // More comprehensive base64 pattern blocking
      .replace(/data:[^;]*;base64/gi, 'unsafe-data')
      // Block expression-based CSS properties 
      .replace(/expression\s*\(|behavior\s*:|@import/gi, 'blocked-code');
      
    logger.debug(`Sanitized input from "${html.slice(0, 30)}..." to "${sanitized.slice(0, 30)}..."`);
    return sanitized;
  } catch (error) {
    // Log the error but return a safe value rather than failing
    logger.error('HTML sanitization error:', error);
    return ''; // Return empty string on error for maximum safety
  }
}

/**
 * Dedicated URL sanitization function for enhanced security
 * Blocks all potentially dangerous URL schemes
 */
function sanitizeUrl(url: string): string {
  if (!url) return url;
  
  try {
    // Decode URL to handle encoded attacks
    const decodedUrl = decodeURIComponent(url.trim());
    
    // Check for dangerous URL schemes - comprehensive list
    const dangerousSchemes = [
      'javascript:', 'data:', 'vbscript:', 'blob:', 
      'mhtml:', 'ms-appx:', 'ms-appdata:',
      'file:', 'ftp:', 'ws:', 'wss:',
      'ms-excel:', 'ms-powerpoint:', 'ms-visio:', 'ms-word:', 'ms-access:'
    ];
    
    // Case-insensitive check against all dangerous schemes
    const lowerUrl = decodedUrl.toLowerCase();
    if (dangerousSchemes.some(scheme => lowerUrl.startsWith(scheme))) {
      logger.warn(`Blocked dangerous URL scheme: ${url.substring(0, 50)}...`);
      return 'about:blank'; // Safe replacement
    }
    
    return url;
  } catch (error) {
    logger.error('URL sanitization error:', error);
    return 'about:blank'; // Safe default on error
  }
}

/**
 * Helper function to recursively sanitize objects with enhanced security
 * Adds protection against prototype pollution, circular references,
 * and deep object traversal attacks
 */
function sanitizeObject(obj: any, depth: number = 0, seen: WeakSet<object> = new WeakSet()): any {
  // Base case - non-objects and null
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  // Prevent stack overflow via recursion depth limit
  if (depth > 100) {
    logger.warn('Maximum sanitization depth reached, truncating object');
    return '[Maximum depth reached]';
  }
  
  // Prevent circular references
  if (seen.has(obj)) {
    return '[Circular Reference]';
  }
  
  // Track this object to detect circular references
  seen.add(obj);
  
  // Handle arrays
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth + 1, seen));
  }
  
  // Create a fresh object with no prototype to prevent pollution
  const sanitized: Record<string, any> = Object.create(null);
  
  // Process each property
  for (const key of Object.getOwnPropertyNames(obj)) {
    // Skip dangerous properties
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
      logger.warn(`Attempted prototype access blocked: ${key}`);
      continue;
    }
    
    try {
      const value = obj[key];
      
      // Handle different value types
      if (typeof value === 'string') {
        // Add URL-specific sanitization for properties that likely contain URLs
        if (['url', 'href', 'src', 'link', 'uri'].some(urlProp => key.toLowerCase().includes(urlProp))) {
          sanitized[key] = sanitizeUrl(sanitizeHtml(value));
        } else {
          sanitized[key] = sanitizeHtml(value);
        }
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeObject(value, depth + 1, seen);
      } else {
        sanitized[key] = value;
      }
    } catch (error) {
      logger.error(`Error sanitizing property "${key}":`, error);
      sanitized[key] = undefined;
    }
  }
  
  return sanitized;
}