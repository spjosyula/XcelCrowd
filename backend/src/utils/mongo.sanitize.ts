import { Types } from 'mongoose';
import { escapeRegExp } from 'lodash';
import { ApiError } from './api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from './logger';
import SPAM_PATTERNS from '../constants/spam.patterns';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

/**
 * Enterprise-grade utility class for MongoDB query sanitization
 * Provides methods to safely build MongoDB queries from user input
 * with robust protection against NoSQL injection attacks
 */
export class MongoSanitizer {
  // Constants for security configuration
  private static readonly MAX_SEARCH_TERM_LENGTH = 100;
  private static readonly MAX_NUMERIC_VALUE = Number.MAX_SAFE_INTEGER;
  private static readonly MIN_NUMERIC_VALUE = Number.MIN_SAFE_INTEGER;
  private static readonly MAX_ARRAY_LENGTH = 100; // Prevent DoS via large arrays



  /**
   * Sanitizes a MongoDB ObjectId string
   * @param id - The ID to sanitize
   * @param entityName - Optional name of the entity for error messages
   * @throws ApiError if the ID is invalid
   */
  static sanitizeObjectId(id: any, entityName = 'document'): Types.ObjectId {
    if (id === undefined || id === null) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${entityName} ID is required`,
        true,
        'INVALID_ID'
      );
    }

    // If it's already an ObjectId, validate integrity and return
    if (id instanceof Types.ObjectId) {
      try {
        // Verify ObjectId validity by forcing string conversion and back
        const idStr = id.toString();
        if (!Types.ObjectId.isValid(idStr)) {
          throw new Error('Invalid ObjectId structure');
        }
        return id;
      } catch (error) {
        logger.warn(`Invalid ObjectId instance received for ${entityName}`, { error });
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid ${entityName} ID format`,
          true,
          'INVALID_ID_FORMAT'
        );
      }
    }

    // Handle string IDs with additional validation
    if (typeof id === 'string') {
      const trimmedId = id.trim();

      // Check for empty strings
      if (trimmedId.length === 0) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${entityName} ID cannot be empty`,
          true,
          'INVALID_ID'
        );
      }

      // Validate ObjectId format with additional checks
      if (!Types.ObjectId.isValid(trimmedId) || trimmedId.length !== 24) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid ${entityName} ID format: Must be a 24-character hexadecimal string`,
          true,
          'INVALID_ID_FORMAT'
        );
      }

      try {
        return new Types.ObjectId(trimmedId);
      } catch (error) {
        logger.warn(`Error creating ObjectId from string: ${trimmedId}`, { error });
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid ${entityName} ID format`,
          true,
          'INVALID_ID_FORMAT'
        );
      }
    }

    // If we got here, the input is neither an ObjectId nor a string
    throw new ApiError(
      HTTP_STATUS.BAD_REQUEST,
      `Invalid ${entityName} ID format: expected string or ObjectId`,
      true,
      'INVALID_ID_FORMAT'
    );
  }

  /**
   * Validates and normalizes a MongoDB ObjectId with enhanced error reporting
   * @param id - The ID to validate (string, ObjectId, or unknown)
   * @param entityName - Name of the entity for context-specific error messages
   * @param options - Additional validation options
   * @returns Normalized ObjectId string
   * @throws ApiError with detailed error information
   */
  static validateObjectId(
    id: string | Types.ObjectId | unknown,
    entityName: string,
    options: {
      required?: boolean;
      errorStatus?: number;
      additionalContext?: string;
    } = {}
  ): string {
    const {
      required = true,
      errorStatus = HTTP_STATUS.BAD_REQUEST,
      additionalContext = ''
    } = options;

    try {
      // Handle undefined or null
      if (id === undefined || id === null) {
        if (required) {
          throw new ApiError(
            errorStatus,
            `${entityName} ID is required${additionalContext ? ': ' + additionalContext : ''}`,
            true,
            'INVALID_ID'
          );
        }
        return '';
      }

      // Handle ObjectId instances
      if (id instanceof Types.ObjectId) {
        return id.toString();
      }

      // Convert to string and trim
      const idString = String(id).trim();

      // Check if empty string
      if (idString === '') {
        if (required) {
          throw new ApiError(
            errorStatus,
            `${entityName} ID cannot be empty${additionalContext ? ': ' + additionalContext : ''}`,
            true,
            'INVALID_ID'
          );
        }
        return '';
      }

      // Enhanced validation for hex string format (24 chars, hex digits only)
      const hexRegex = /^[0-9a-fA-F]{24}$/;
      if (!hexRegex.test(idString)) {
        throw new ApiError(
          errorStatus,
          `Invalid ${entityName} ID format: Must be a 24-character hexadecimal string` +
          `${additionalContext ? '. ' + additionalContext : ''}`,
          true,
          'INVALID_ID_FORMAT'
        );
      }

      // Final validation using Mongoose's isValid (extra layer of defense)
      if (!Types.ObjectId.isValid(idString)) {
        throw new ApiError(
          errorStatus,
          `Invalid ${entityName} ID format: Failed structural validation` +
          `${additionalContext ? '. ' + additionalContext : ''}`,
          true,
          'INVALID_ID_FORMAT'
        );
      }

      return idString;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      // Catch any unexpected errors and convert to ApiError
      logger.error(`Unexpected error validating ObjectId for ${entityName}:`, error);

      const errorMessage = error instanceof Error ? error.message : String(error);

      throw new ApiError(
        errorStatus,
        `Invalid ${entityName} ID format: ${errorMessage}`,
        true,
        'INVALID_ID_FORMAT'
      );
    }
  }

  /**
 * Sanitizes HTML content with comprehensive XSS protection
 * Uses a whitelist approach to ensure only safe HTML elements and attributes are permitted
 * @param html - The HTML content to sanitize
 * @param options - Configuration options for HTML sanitization
 * @returns Safely sanitized HTML string
 * @throws ApiError with detailed error information
 */
  static sanitizeHtml(
    html: unknown,
    options: {
      fieldName?: string;
      maxLength?: number;
      allowedTags?: string[];
      allowedAttributes?: Record<string, string[]>;
      allowedSchemes?: string[];
      stripAllTags?: boolean;
      allowIframes?: boolean;
      requireNoopener?: boolean;
      logSuspiciousContent?: boolean;
    } = {}
  ): string {
    const {
      fieldName = 'HTML content',
      maxLength = 100000,
      allowedTags = ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre', 'hr', 'span', 'div', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
      allowedAttributes = {
        a: ['href', 'title', 'target', 'rel'],
        img: ['src', 'alt', 'title', 'width', 'height'],
        div: ['class', 'id', 'style'],
        span: ['class', 'id', 'style'],
        table: ['class', 'id', 'style', 'border', 'cellpadding', 'cellspacing'],
        th: ['scope', 'colspan', 'rowspan', 'style', 'class'],
        td: ['colspan', 'rowspan', 'style', 'class'],
        p: ['class', 'style'],
        code: ['class'],
        pre: ['class']
      },
      allowedSchemes = ['http', 'https', 'mailto', 'tel'],
      stripAllTags = false,
      allowIframes = false,
      requireNoopener = true,
      logSuspiciousContent = true
    } = options;

    try {
      // Validate input type and length
      if (html === null || html === undefined) {
        return '';
      }

      let htmlString = String(html);

      // Apply length limits to prevent DoS attacks
      if (htmlString.length > maxLength) {
        logger.warn(`HTML content exceeded maximum length (${htmlString.length} > ${maxLength})`, {
          contentLength: htmlString.length,
          maxAllowed: maxLength,
          fieldName
        });

        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${fieldName} exceeds maximum allowed length (${maxLength} characters)`,
          true,
          'HTML_CONTENT_TOO_LONG'
        );
      }

      // Log suspicious content if enabled
      if (logSuspiciousContent) {
        const suspiciousPatterns = [
          /<script/i, /javascript:/i, /data:text\/html/i, /expression\s*\(/i,
          /eval\s*\(/i, /vbscript:/i, /document\./i, /window\./i, /on\w+=/i
        ];

        const suspiciousMatches = suspiciousPatterns
          .map(pattern => pattern.test(htmlString) ? pattern.toString() : null)
          .filter(Boolean);

        if (suspiciousMatches.length > 0) {
          logger.warn(`Potentially malicious HTML content detected`, {
            patterns: suspiciousMatches,
            fieldName,
            contentPreview: htmlString.substring(0, 200) + (htmlString.length > 200 ? '...' : '')
          });
        }
      }

      // Option to strip all HTML tags
      if (stripAllTags) {
        // Instead of regex, use DOMPurify with all tags forbidden
        return DOMPurify.sanitize(htmlString, { ALLOWED_TAGS: [] });
      }

      // Set up DOMPurify configuration based on our options
      const purifyConfig: any = {
        ALLOWED_TAGS: allowedTags,
        ALLOWED_ATTR: [],
        ALLOWED_URI_REGEXP: new RegExp(`^(?:${allowedSchemes.join('|')})`, 'i'),
        ADD_TAGS: allowIframes ? ['iframe'] : [],
        ADD_ATTR: [],
        FORCE_BODY: true,
        USE_PROFILES: { html: true }
      };

      // Add allowed attributes
      for (const [tag, attrs] of Object.entries(allowedAttributes)) {
        attrs.forEach(attr => {
          if (!purifyConfig.ALLOWED_ATTR.includes(attr)) {
            purifyConfig.ALLOWED_ATTR.push(attr);
          }
        });
      }

      // If iframes are allowed, add iframe attributes
      if (allowIframes) {
        ['src', 'width', 'height', 'frameborder', 'allowfullscreen', 'allow', 'title'].forEach(attr => {
          if (!purifyConfig.ALLOWED_ATTR.includes(attr)) {
            purifyConfig.ALLOWED_ATTR.push(attr);
          }
        });
      }

      // Handle target="_blank" with proper security
      if (requireNoopener) {
        purifyConfig.FORBID_ATTR = ['target'];
        purifyConfig.ADD_ATTR = ['target', 'rel'];

        // Add hook to ensure proper rel attribute for target="_blank"
        purifyConfig.HOOKS = {
          afterSanitizeAttributes: (node: Element) => {
            if (node.tagName === 'A' && node.hasAttribute('target') && node.getAttribute('target') === '_blank') {
              node.setAttribute('rel', 'noopener noreferrer');
            }
          }
        };
      }

      // Perform the actual sanitization with DOMPurify
      const sanitizedHtml = DOMPurify.sanitize(htmlString, purifyConfig);

      // Final safety check
      const dangerousContent = /<script|javascript:|data:text\/html|eval\s*\(|expression\s*\(/i.test(String(sanitizedHtml));
      if (dangerousContent) {
        logger.error(`Sanitization failed to remove all potentially dangerous content`, {
          fieldName,
          beforeLength: htmlString.length,
          afterLength: String(sanitizedHtml).length
        });

        // If final output still contains suspicious patterns, fall back to complete stripping
        return DOMPurify.sanitize(String(sanitizedHtml), { ALLOWED_TAGS: [] });
      }

      return String(sanitizedHtml);
    } catch (error) {
      logger.error(`Error sanitizing HTML content:`, error);

      // If any error occurs during sanitization, return empty string or throw
      if (error instanceof ApiError) {
        throw error;
      }

      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Failed to sanitize ${fieldName}: ${error instanceof Error ? error.message : String(error)}`,
        true,
        'HTML_SANITIZATION_ERROR'
      );
    }
  }

  /**
   * Safely creates an equality condition for MongoDB queries
   * Prevents NoSQL injection by ensuring the value is treated as a literal
   * @param value - The value to use in the equality condition
   */
  static buildEqualityCondition(value: any): { $eq: any } {
    // Detect potential object injection attempts
    if (value !== null && typeof value === 'object') {
      // For security, don't allow direct objects in equality conditions
      // unless they are ObjectId instances or Dates
      if (!(value instanceof Types.ObjectId) && !(value instanceof Date) && !Array.isArray(value)) {
        logger.warn('Potential NoSQL injection attempt: Object passed to equality condition', {
          valueType: typeof value,
          valuePrototype: Object.prototype.toString.call(value)
        });
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid query value: Objects not allowed in equality conditions',
          true,
          'INVALID_QUERY_VALUE'
        );
      }

      // For arrays, validate each element
      if (Array.isArray(value)) {
        // Prevent DoS via large arrays
        if (value.length > this.MAX_ARRAY_LENGTH) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Array exceeds maximum allowed length (${this.MAX_ARRAY_LENGTH})`,
            true,
            'ARRAY_TOO_LARGE'
          );
        }

        // Recursively validate array elements
        const safeArray = value.map(item => {
          if (item !== null && typeof item === 'object' && !(item instanceof Types.ObjectId) && !(item instanceof Date)) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              'Invalid query value: Objects not allowed in equality array conditions',
              true,
              'INVALID_QUERY_VALUE'
            );
          }
          return item;
        });

        return { $eq: safeArray };
      }
    }

    return { $eq: value };
  }

  /**
   * Safely creates a regex search condition for MongoDB
   * Escapes special regex characters to prevent ReDoS attacks
   * @param searchTerm - The search term
   * @param options - MongoDB regex options (default: 'i' for case-insensitive)
   */
  static buildSafeRegexCondition(
    searchTerm: string,
    options = 'i',
    maxLength = this.MAX_SEARCH_TERM_LENGTH
  ): { $regex: string, $options: string } {
    if (searchTerm === undefined || searchTerm === null || typeof searchTerm !== 'string') {
      return { $regex: '', $options: options };
    }

    // Validate options to prevent injection
    const safeOptions = options.replace(/[^imsuUxJ]/g, '');
    if (safeOptions !== options) {
      logger.warn('Potentially unsafe regex options sanitized', {
        original: options,
        sanitized: safeOptions
      });
    }

    // Trim and validate search term length to prevent DoS
    const trimmedTerm = searchTerm.trim();
    if (trimmedTerm.length > maxLength) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Search term exceeds maximum allowed length (${maxLength} characters)`,
        true,
        'SEARCH_TERM_TOO_LONG'
      );
    }

    // Escape regex special characters to prevent ReDoS
    const sanitizedTerm = escapeRegExp(trimmedTerm);

    // Add additional complexity validation to prevent ReDoS
    if (this.hasExcessiveRepetition(sanitizedTerm)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Search term contains excessive repetition patterns',
        true,
        'UNSAFE_SEARCH_PATTERN'
      );
    }

    return { $regex: sanitizedTerm, $options: safeOptions };
  }

  /**
   * Detects patterns that could lead to catastrophic backtracking
   * @param pattern - The string pattern to check
   * @returns True if potentially dangerous pattern detected
   */
  private static hasExcessiveRepetition(pattern: string): boolean {
    // Check for repeated characters (more than 10 of the same character)
    const repeatedCharsRegex = /(.)\1{10,}/;
    if (repeatedCharsRegex.test(pattern)) {
      return true;
    }

    // Check for repeated sequences (e.g., "abcabc" repeated many times)
    for (let seqLength = 2; seqLength <= 10; seqLength++) {
      for (let i = 0; i <= pattern.length - (seqLength * 2); i++) {
        const seq = pattern.substr(i, seqLength);
        let count = 0;
        let pos = i;

        while (pos <= pattern.length - seqLength) {
          if (pattern.substr(pos, seqLength) === seq) {
            count++;
            pos += seqLength;
            if (count > 5) return true; // More than 5 repetitions is risky
          } else {
            break;
          }
        }
      }
    }

    return false;
  }

  /**
 * Sanitizes a string value with comprehensive validation and security checks
 * Protects against XSS, NoSQL injection, and buffer overflow attacks
 * @param value - The string value to sanitize
 * @param options - Configuration options for sanitization
 * @returns Safely sanitized string
 */
  static sanitizeString(
    value: unknown,
    options: {
      fieldName?: string;
      maxLength?: number;
      minLength?: number;
      required?: boolean;
      trim?: boolean;
      allowNull?: boolean;
      pattern?: RegExp;
      patternErrorMessage?: string;
      transformations?: Array<(s: string) => string>;
    } = {}
  ): string {
    const {
      fieldName = 'String',
      maxLength = 1000,
      minLength = 0,
      required = true,
      trim = true,
      allowNull = false,
      pattern,
      patternErrorMessage,
      transformations = []
    } = options;

    // Handle null/undefined values
    if (value === null) {
      if (allowNull) return '';
      if (required) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${fieldName} is required`,
          true,
          'REQUIRED_FIELD_MISSING'
        );
      }
      return '';
    }

    if (value === undefined) {
      if (required) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${fieldName} is required`,
          true,
          'REQUIRED_FIELD_MISSING'
        );
      }
      return '';
    }

    // Coerce to string and trim if needed
    let sanitized = String(value);
    if (trim) sanitized = sanitized.trim();

    // Validate minimum length
    if (sanitized.length < minLength) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} must be at least ${minLength} characters long`,
        true,
        'STRING_TOO_SHORT'
      );
    }

    // Validate maximum length to prevent DoS attacks
    if (sanitized.length > maxLength) {
      // More secure logging - obscure the actual field name for sensitive fields
      const isSensitiveField = /password|credential|token|key|secret|auth/i.test(fieldName);
      const logFieldName = isSensitiveField ? 'Sensitive field' : fieldName;

      // Log with minimal information that can't be exploited
      logger.warn(`Input exceeds maximum length limits`, {
        field: logFieldName,
        lengthCategory: sanitized.length > maxLength * 2 ? 'Extreme' : 'Exceeded',
        // Avoid logging exact length for potential DoS detection evasion
        percentExceeded: Math.round((sanitized.length / maxLength - 1) * 100)
      });

      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} exceeds maximum allowed length (${maxLength} characters)`,
        true,
        'STRING_TOO_LONG'
      );
    }

    // Apply custom pattern validation if provided
    if (pattern && !pattern.test(sanitized)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        patternErrorMessage || `${fieldName} does not match required format`,
        true,
        'INVALID_STRING_FORMAT'
      );
    }

    // Apply any custom transformations
    for (const transform of transformations) {
      sanitized = transform(sanitized);
    }

    // Check for potentially dangerous content like MongoDB operators
    if (sanitized.includes("$") || sanitized.includes("{") && sanitized.includes("}")) {
      // Escape all potential MongoDB operator characters
      sanitized = escapeRegExp(sanitized);
      logger.debug(`Potentially unsafe string sanitized in ${fieldName}`);
    }

    return sanitized;
  }

  /**
   * Sanitizes and validates an email address with enterprise-grade security
   * Performs RFC 5322 compliant validation with protection against injection attacks
   * @param email - The email address to sanitize
   * @param options - Configuration options for email sanitization
   * @returns Sanitized and normalized email address
   */
  static sanitizeEmail(
    email: unknown,
    options: {
      fieldName?: string;
      required?: boolean;
      maxLength?: number;
      allowedDomains?: string[];
      blockedDomains?: string[];
    } = {}
  ): string {
    const {
      fieldName = 'Email',
      required = true,
      maxLength = 254, // Max email length per RFC 5321
      allowedDomains = [],
      blockedDomains = []
    } = options;

    // First perform basic string sanitization
    const sanitized = this.sanitizeString(email, {
      fieldName,
      required,
      maxLength,
      trim: true,
      transformations: [str => str.toLowerCase()] // Email addresses are case-insensitive
    });

    // Empty string already handled by sanitizeString if required=true
    if (!sanitized) return sanitized;

    // Advanced email format validation - RFC 5322 compliant
    // This is a comprehensive regex that handles the complexity of the email specification
    const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

    if (!emailRegex.test(sanitized)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} is not a valid email address`,
        true,
        'INVALID_EMAIL_FORMAT'
      );
    }

    // Extract domain for additional validation
    const domain = sanitized.split('@')[1].toLowerCase();

    // Check blocked domains
    if (blockedDomains.length > 0 && blockedDomains.includes(domain)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Email domain ${domain} is not allowed`,
        true,
        'BLOCKED_EMAIL_DOMAIN'
      );
    }

    // Restrict to allowed domains if list is provided
    if (allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Email domain ${domain} is not in the list of allowed domains`,
        true,
        'UNAUTHORIZED_EMAIL_DOMAIN'
      );
    }

    // Check for unicode homograph attacks and lookalike domains
    const containsPunycode = domain.includes('xn--');
    if (containsPunycode) {
      logger.warn(`Punycode detected in email domain: ${domain}`, {
        email: sanitized,
        domain
      });

      // You may want to implement additional homograph attack prevention here
      // or just flag it for review in high-security environments
    }

    // Log email validation for security audit
    logger.debug(`Email validated successfully: ${sanitized.substring(0, 3)}...@${domain}`);

    return sanitized;
  }

  /**
   * Sanitizes a username with specialized rules for user identification
   * Protects against injection and ensures username policy compliance
   * @param username - The username to sanitize
   * @param options - Configuration options for username sanitization
   * @returns Sanitized username
   */
  static sanitizeUsername(
    username: unknown,
    options: {
      fieldName?: string;
      minLength?: number;
      maxLength?: number;
      allowedPattern?: RegExp;
      required?: boolean;
      allowedCharacters?: string;
    } = {}
  ): string {
    const {
      fieldName = 'Username',
      minLength = 3,
      maxLength = 50,
      allowedPattern = /^[a-zA-Z0-9_\-.]+$/,
      required = true,
      allowedCharacters = 'alphanumeric characters, hyphens, underscores, and periods'
    } = options;

    // Basic string sanitization
    const sanitized = this.sanitizeString(username, {
      fieldName,
      minLength,
      maxLength,
      required,
      trim: true,
      pattern: allowedPattern,
      patternErrorMessage: `${fieldName} may only contain ${allowedCharacters}`
    });

    // Check for common username patterns used in NoSQL injection attacks
    const suspiciousPatterns = [
      /\.\$/, /\$\{/, /\$ne/, /\$gt/, /\$where/, /\$regex/,
      /\$in/, /\$exists/, /javascript/i, /eval\(/i
    ];

    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => pattern.test(sanitized));
    if (hasSuspiciousPattern) {
      logger.warn(`Potentially malicious username pattern detected: ${sanitized}`, {
        username: sanitized.substring(0, 15) + (sanitized.length > 15 ? '...' : '')
      });

      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} contains disallowed patterns`,
        true,
        'UNSAFE_USERNAME_PATTERN'
      );
    }

    return sanitized;
  }

  /**
   * Sanitizes a secure password with password policy enforcement
   * Ensures password complexity and prevents common password attacks
   * @param password - The password to sanitize
   * @param options - Configuration options for password sanitization
   * @returns Sanitized password
   */
  static sanitizePassword(
    password: unknown,
    options: {
      fieldName?: string;
      minLength?: number;
      maxLength?: number;
      requireUppercase?: boolean;
      requireLowercase?: boolean;
      requireNumbers?: boolean;
      requireSpecialChars?: boolean;
      disallowCommonPasswords?: boolean;
    } = {}
  ): string {
    const {
      fieldName = 'Password',
      minLength = 8,
      maxLength = 128,
      requireUppercase = true,
      requireLowercase = true,
      requireNumbers = true,
      requireSpecialChars = true,
      disallowCommonPasswords = true
    } = options;

    // Basic sanitization without pattern validation (we'll do custom validation)
    const sanitized = this.sanitizeString(password, {
      fieldName,
      minLength,
      maxLength,
      required: true,
      trim: false // Don't trim passwords as spaces might be intentional
    });

    let validationErrors = [];

    // Password complexity validation
    if (requireUppercase && !/[A-Z]/.test(sanitized)) {
      validationErrors.push('at least one uppercase letter');
    }

    if (requireLowercase && !/[a-z]/.test(sanitized)) {
      validationErrors.push('at least one lowercase letter');
    }

    if (requireNumbers && !/\d/.test(sanitized)) {
      validationErrors.push('at least one number');
    }

    if (requireSpecialChars && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(sanitized)) {
      validationErrors.push('at least one special character');
    }

    if (validationErrors.length > 0) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} must contain ${validationErrors.join(', ')}`,
        true,
        'PASSWORD_COMPLEXITY_ERROR'
      );
    }

    // Check for common passwords (optional, would need a common password list)
    if (disallowCommonPasswords) {
      const commonPasswords = ['password', 'qwerty', '123456', 'admin1234']; // Example list, replace with a proper one
      const passwordLower = sanitized.toLowerCase();

      if (commonPasswords.includes(passwordLower)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${fieldName} is too common and easily guessable`,
          true,
          'COMMON_PASSWORD_ERROR'
        );
      }
    }

    return sanitized;
  }

  /**
   * Sanitizes URL input with comprehensive security checks
   * Protects against URL-based attacks including XSS, open redirect, and SSRF
   * @param url - The URL to sanitize
   * @param options - Configuration options for URL sanitization
   * @returns Sanitized URL
   */
  static sanitizeUrl(
    url: unknown,
    options: {
      fieldName?: string;
      required?: boolean;
      maxLength?: number;
      allowedProtocols?: string[];
      allowedDomains?: string[];
      allowRelative?: boolean;
    } = {}
  ): string {
    const {
      fieldName = 'URL',
      required = true,
      maxLength = 2048,
      allowedProtocols = ['https', 'http'],
      allowedDomains = [],
      allowRelative = false
    } = options;

    // Basic string sanitization
    const sanitized = this.sanitizeString(url, {
      fieldName,
      maxLength,
      required,
      trim: true
    });

    if (!sanitized && !required) {
      return '';
    }

    try {
      // For relative URLs
      if (allowRelative && sanitized.startsWith('/')) {
        // Validate relative URL format
        if (!/^\/[^/].*$/.test(sanitized)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `${fieldName} is not a valid relative URL`,
            true,
            'INVALID_RELATIVE_URL'
          );
        }
        return sanitized;
      }

      // Parse URL to validate and extract components
      const parsedUrl = new URL(sanitized);

      // Protocol validation
      const protocol = parsedUrl.protocol.replace(':', '');
      if (!allowedProtocols.includes(protocol)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `URL protocol '${protocol}' is not allowed. Allowed protocols: ${allowedProtocols.join(', ')}`,
          true,
          'DISALLOWED_URL_PROTOCOL'
        );
      }

      // Domain validation if allowedDomains is specified
      if (allowedDomains.length > 0) {
        const hostname = parsedUrl.hostname.toLowerCase();
        const isDomainAllowed = allowedDomains.some(domain =>
          hostname === domain || hostname.endsWith(`.${domain}`)
        );

        if (!isDomainAllowed) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `URL domain '${parsedUrl.hostname}' is not allowed`,
            true,
            'DISALLOWED_URL_DOMAIN'
          );
        }
      }

      // Check for potentially dangerous content in URL parameters
      const hasScriptInParams = /[?&].*script.*=/.test(sanitized) ||
        /[?&].*<.*>.*=/.test(sanitized);
      if (hasScriptInParams) {
        logger.warn(`Potentially malicious script content in URL params: ${sanitized}`);
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `${fieldName} contains potentially unsafe parameters`,
          true,
          'UNSAFE_URL_PARAMETERS'
        );
      }

      return sanitized;
    } catch (error) {
      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${fieldName} is not a valid URL: ${error instanceof Error ? error.message : String(error)}`,
        true,
        'INVALID_URL_FORMAT'
      );
    }
  }

  /**
 * Sanitize and validate GitHub URL with comprehensive security
 * @param urlString - The URL to sanitize
 * @returns Sanitized URL or null if invalid
 */
  static sanitizeGitHubUrl(urlString: string): string | null {
    if (!urlString) return null;

    // Check for common URL shorteners - we don't allow these for security reasons
    for (const domain of SPAM_PATTERNS.SUSPICIOUS_DOMAINS) {
      if (urlString.includes(domain)) {
        logger.warn(`Submission URL contains suspicious domain: ${domain}`, {
          submissionUrl: urlString
        });
        return null;
      }
    }

    try {
      // Handle URLs without protocol
      let urlWithProtocol = urlString;
      if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
        urlWithProtocol = `https://${urlString}`;
      }

      // Parse and validate URL
      const url = new URL(urlWithProtocol);

      // Only allow http and https protocols
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        logger.warn(`URL protocol not allowed: ${url.protocol}`, {
          submissionUrl: urlString
        });
        return null;
      }

      // Always use HTTPS for security
      url.protocol = 'https:';

      // Convert hostname to lowercase for consistent validation
      url.hostname = url.hostname.toLowerCase();

      // Check for potentially dangerous content in URL parameters
      const hasScriptInParams = /[?&][^=]*script[^=]*=/.test(url.search) ||
        /[?&][^=]*<[^=]*>[^=]*=/.test(url.search);
      if (hasScriptInParams) {
        logger.warn(`Potentially malicious script content in URL params`, {
          submissionUrl: urlString,
          search: url.search
        });
        return null;
      }

      return url.toString();
    } catch (error) {
      logger.warn(`Invalid URL format`, {
        submissionUrl: urlString,
        error: error instanceof Error ? error.message : String(error)
      });
      return null;
    }
  }

  /**
   * Safely creates a numeric range condition with boundary checks
   * Prevents integer overflow/underflow attacks and validates numeric types
   * @param min - Minimum value (optional)
   * @param max - Maximum value (optional)
   */
  static buildNumericRangeCondition(
    min?: number,
    max?: number,
    options: {
      absoluteMin?: number;
      absoluteMax?: number;
    } = {}
  ): Record<string, number> {
    const {
      absoluteMin = this.MIN_NUMERIC_VALUE,
      absoluteMax = this.MAX_NUMERIC_VALUE
    } = options;

    const rangeCondition: Record<string, number> = {};

    if (min !== undefined) {
      // Enhanced type checking
      if (typeof min !== 'number' || isNaN(min) || !isFinite(min)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Minimum value must be a valid finite number',
          true,
          'INVALID_MIN_VALUE'
        );
      }

      // Boundary checking to prevent overflow attacks
      if (min < absoluteMin) {
        logger.warn(`Minimum value ${min} below absolute minimum ${absoluteMin}, adjusting`);
        rangeCondition.$gte = absoluteMin;
      } else if (min > absoluteMax) {
        logger.warn(`Minimum value ${min} above absolute maximum ${absoluteMax}, adjusting`);
        rangeCondition.$gte = absoluteMax;
      } else {
        rangeCondition.$gte = min;
      }
    }

    if (max !== undefined) {
      // Enhanced type checking
      if (typeof max !== 'number' || isNaN(max) || !isFinite(max)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Maximum value must be a valid finite number',
          true,
          'INVALID_MAX_VALUE'
        );
      }

      // Boundary checking to prevent overflow attacks
      if (max > absoluteMax) {
        logger.warn(`Maximum value ${max} above absolute maximum ${absoluteMax}, adjusting`);
        rangeCondition.$lte = absoluteMax;
      } else if (max < absoluteMin) {
        logger.warn(`Maximum value ${max} below absolute minimum ${absoluteMin}, adjusting`);
        rangeCondition.$lte = absoluteMin;
      } else {
        rangeCondition.$lte = max;
      }
    }

    // Logical validation of range (min <= max)
    if (min !== undefined && max !== undefined && rangeCondition.$gte > rangeCondition.$lte) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid range: minimum value cannot be greater than maximum value',
        true,
        'INVALID_RANGE'
      );
    }

    return rangeCondition;
  }

  /**
   * Validates sorting parameters with enhanced security checks
   * @param sortBy - Field to sort by
   * @param sortOrder - Sort direction ('asc' or 'desc')
   * @param allowedFields - Array of allowed fields for sorting
   */
  static validateSortParams(
    sortBy: string,
    sortOrder: 'asc' | 'desc',
    allowedFields: string[] = []
  ): { sortBy: string, sortOrder: 1 | -1 } {
    // Type checking for sortBy
    if (typeof sortBy !== 'string') {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Sort field must be a string',
        true,
        'INVALID_SORT_FIELD_TYPE'
      );
    }

    // Sanitize sortBy to prevent injection (remove any $ prefixed fields)
    const sanitizedSortBy = sortBy.replace(/^\$+/, '');
    if (sanitizedSortBy !== sortBy) {
      logger.warn(`Potentially malicious sort field sanitized: ${sortBy} -> ${sanitizedSortBy}`);
    }

    // Prevent dot notation traversal attacks by limiting depth
    if (sanitizedSortBy.split('.').length > 3) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Sort field hierarchy too deep (max 3 levels)',
        true,
        'INVALID_SORT_FIELD_DEPTH'
      );
    }

    // Validate against allowed fields if provided
    if (allowedFields.length > 0) {
      // Check if the field (or its root in case of dot notation) is allowed
      const rootField = sanitizedSortBy.split('.')[0];
      const isFieldAllowed = allowedFields.some(field => {
        // Exact match
        if (field === sanitizedSortBy) return true;
        // Root field match for dot notation fields
        if (field === rootField) return true;
        // Path prefix match
        if (sanitizedSortBy.startsWith(`${field}.`)) return true;
        return false;
      });

      if (!isFieldAllowed) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid sort field. Allowed fields: ${allowedFields.join(', ')}`,
          true,
          'INVALID_SORT_FIELD'
        );
      }
    }

    // Validate sortOrder
    if (sortOrder !== 'asc' && sortOrder !== 'desc') {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Sort order must be either "asc" or "desc"',
        true,
        'INVALID_SORT_ORDER'
      );
    }

    return {
      sortBy: sanitizedSortBy,
      sortOrder: sortOrder === 'asc' ? 1 : -1
    };
  }

  /**
   * Safely builds a MongoDB query object from user input with comprehensive security checks
   * @param baseQuery - Initial query object to extend
   * @param filters - User-provided filters
   * @param allowedFilters - Map of allowed filters and their types
   * @param enumValues - Map of allowed enum values for enum filters
   */
  static buildSafeQuery(
    baseQuery: Record<string, any>,
    filters: Record<string, any>,
    allowedFilters: Record<string, 'string' | 'number' | 'boolean' | 'objectId' | 'enum' | 'regex' | 'date' | 'array'>,
    enumValues: Record<string, string[]> = {}
  ): Record<string, any> {
    // Clone the base query to avoid mutations
    const safeQuery = JSON.parse(JSON.stringify(baseQuery));

    // Quick exit if no filters
    if (!filters || typeof filters !== 'object' || filters === null) {
      return safeQuery;
    }

    // Validate against prototype pollution
    if ('__proto__' in filters || 'constructor' in filters || 'prototype' in filters) {
      logger.warn('Potential prototype pollution attempt detected in query filters', {
        suspicious: Object.keys(filters).filter(k => ['__proto__', 'constructor', 'prototype'].includes(k))
      });
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid query parameters',
        true,
        'INVALID_QUERY_PARAMETERS'
      );
    }

    // Process only allowed filters with enhanced security
    for (const [key, type] of Object.entries(allowedFilters)) {
      if (!(key in filters) || filters[key] === undefined || filters[key] === null) {
        continue;
      }

      const value = filters[key];

      try {
        switch (type) {
          case 'string':
            if (typeof value !== 'string') {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a string`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }

            // At this point, TypeScript knows value is a string
            const stringValue: string = value;

            // Validate string length to prevent DoS
            if (stringValue.length > 1000) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} exceeds maximum allowed length (1000 characters)`,
                true,
                'STRING_TOO_LONG'
              );
            }

            safeQuery[key] = this.buildEqualityCondition(stringValue);
            break;

          case 'number':
            let numValue: number;

            // Handle string numbers
            if (typeof value === 'string') {
              const stringValue = value as string;
              if (!stringValue.trim() || isNaN(Number(stringValue))) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${key} must be a valid number`,
                  true,
                  'INVALID_FILTER_TYPE'
                );
              }
              numValue = Number(value);
            } else if (typeof value === 'number') {
              if (!isFinite(value) || isNaN(value)) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${key} must be a finite number`,
                  true,
                  'INVALID_FILTER_TYPE'
                );
              }
              numValue = value;
            } else {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a number`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }

            // Boundary check numbers
            if (numValue < this.MIN_NUMERIC_VALUE || numValue > this.MAX_NUMERIC_VALUE) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} is outside allowable numeric range`,
                true,
                'NUMERIC_RANGE_ERROR'
              );
            }

            safeQuery[key] = this.buildEqualityCondition(numValue);
            break;

          case 'boolean':
            let boolValue: boolean;

            if (typeof value === 'boolean') {
              boolValue = value;
            } else if (value === 'true' || value === '1' || value === 1) {
              boolValue = true;
            } else if (value === 'false' || value === '0' || value === 0) {
              boolValue = false;
            } else {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a boolean value (true/false, 1/0)`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }

            safeQuery[key] = this.buildEqualityCondition(boolValue);
            break;

          case 'objectId':
            // Use sanitizeObjectId for the most robust validation
            safeQuery[key] = this.sanitizeObjectId(value, key);
            break;

          case 'date':
            let dateValue: Date;

            // Handle string dates or Date objects
            if (value === null || value === undefined) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a valid date`,
                true,
                'INVALID_DATE_FORMAT'
              );
            } else if (Object.prototype.toString.call(value) === '[object Date]') {
              // Using Object.prototype.toString is more reliable than instanceof for type checking
              const tempDate = value as Date;
              if (isNaN(tempDate.getTime())) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${key} contains an invalid date value`,
                  true,
                  'INVALID_DATE_FORMAT'
                );
              }
              dateValue = tempDate;
            } else if (typeof value === 'string' || typeof value === 'number') {
              const parsedDate = new Date(value);

              // Validate date parsing worked
              if (isNaN(parsedDate.getTime())) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${key} must be a valid date`,
                  true,
                  'INVALID_DATE_FORMAT'
                );
              }

              dateValue = parsedDate;
            } else {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a valid date`,
                true,
                'INVALID_DATE_FORMAT'
              );
            }

            safeQuery[key] = this.buildEqualityCondition(dateValue);
            break;

          case 'enum':
            if (!enumValues[key]) {
              throw new ApiError(
                HTTP_STATUS.INTERNAL_SERVER_ERROR,
                `Enum values not provided for ${key}`,
                true,
                'MISSING_ENUM_VALUES'
              );
            }

            // Handle case-sensitive/insensitive comparison based on enum values
            const matchFound = typeof value === 'string' &&
              enumValues[key].some(enumVal =>
                // Use exact comparison for case sensitivity
                enumVal === value
              );

            if (!matchFound) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `Invalid value for ${key}. Allowed values: ${enumValues[key].join(', ')}`,
                true,
                'INVALID_ENUM_VALUE'
              );
            }

            safeQuery[key] = this.buildEqualityCondition(value);
            break;

          case 'regex':
            if (typeof value !== 'string') {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a string for search`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }

            safeQuery[key] = this.buildSafeRegexCondition(value);
            break;

          case 'array':
            // Validate array or convert single value to array
            let arrayValue: any[];

            if (Array.isArray(value)) {
              arrayValue = value;
            } else {
              // Convert single value to array for convenience
              arrayValue = [value];
            }

            // Limit array size to prevent DoS
            if (arrayValue.length > this.MAX_ARRAY_LENGTH) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} array exceeds maximum allowed length (${this.MAX_ARRAY_LENGTH})`,
                true,
                'ARRAY_TOO_LARGE'
              );
            }

            safeQuery[key] = { $in: arrayValue };
            break;

          default:
            logger.warn(`Unknown filter type: ${type} for key: ${key}`);
            continue;
        }
      } catch (error: unknown) {
        if (error instanceof ApiError) throw error;

        // Log the actual error for system monitoring
        logger.error(`Error processing filter ${key}:`, error);

        // Extract error message safely
        const errorMessage = error instanceof Error ? error.message : String(error);

        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid filter: ${key} - ${errorMessage}`,
          true,
          'INVALID_FILTER'
        );
      }
    }

    return safeQuery;
  }

  /**
   * Safely sanitizes MongoDB update operations
   * Prevents NoSQL operator injection in update documents
   * @param updateData - The update data to sanitize
   * @param allowedFields - Array of allowed fields
   */
  static sanitizeUpdateOperations(
    updateData: Record<string, any>,
    allowedFields: string[] = []
  ): Record<string, any> {
    // Clone to avoid mutations
    const sanitized: Record<string, any> = {};

    if (!updateData || typeof updateData !== 'object' || updateData === null) {
      return sanitized;
    }

    // Detect MongoDB update operators ($set, $push, etc.)
    const hasUpdateOperators = Object.keys(updateData).some(key => key.startsWith('$'));

    if (hasUpdateOperators) {
      // Handle update operators document
      for (const [operator, fields] of Object.entries(updateData)) {
        // Only allow whitelisted MongoDB update operators
        const allowedOperators = ['$set', '$inc', '$push', '$pull', '$addToSet', '$unset'];

        if (!operator.startsWith('$') || !allowedOperators.includes(operator)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid update operator: ${operator}`,
            true,
            'INVALID_UPDATE_OPERATOR'
          );
        }

        if (!fields || typeof fields !== 'object' || fields === null) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Invalid fields for operator ${operator}`,
            true,
            'INVALID_UPDATE_FIELDS'
          );
        }

        sanitized[operator] = {};

        // Process each field for this operator
        for (const [field, value] of Object.entries(fields)) {
          // Check if field is allowed
          if (allowedFields.length > 0 && !this.isFieldAllowed(field, allowedFields)) {
            throw new ApiError(
              HTTP_STATUS.BAD_REQUEST,
              `Field '${field}' is not allowed for updates`,
              true,
              'UNAUTHORIZED_FIELD_UPDATE'
            );
          }

          // Prevent MongoDB operator injection in values
          if (value !== null && typeof value === 'object' && !Array.isArray(value) &&
            !(value instanceof Date) && !(value instanceof Types.ObjectId)) {

            // Special handling for $push and $addToSet with $each
            if ((operator === '$push' || operator === '$addToSet') &&
              Object.keys(value).length === 1 && '$each' in value) {

              if (!Array.isArray(value.$each)) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${operator}.$each must be an array`,
                  true,
                  'INVALID_EACH_OPERATOR'
                );
              }

              // Validate array size
              if (value.$each.length > this.MAX_ARRAY_LENGTH) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `${operator}.$each array exceeds maximum allowed length`,
                  true,
                  'ARRAY_TOO_LARGE'
                );
              }

              // Recursively sanitize each array item
              sanitized[operator][field] = {
                $each: value.$each.map((item: any) => this.sanitizeValue(item))
              };
            } else {
              // For other objects, check for MongoDB operators
              const hasOperators = Object.keys(value).some(k => k.startsWith('$'));
              if (hasOperators) {
                throw new ApiError(
                  HTTP_STATUS.BAD_REQUEST,
                  `MongoDB operators not allowed in update values`,
                  true,
                  'INVALID_UPDATE_VALUE'
                );
              }

              // Deep clone to prevent object reference issues
              sanitized[operator][field] = JSON.parse(JSON.stringify(value));
            }
          } else {
            // For primitive values, arrays, dates, and ObjectIds
            sanitized[operator][field] = this.sanitizeValue(value);
          }
        }
      }
    } else {
      // Handle direct update document (implicitly $set)
      sanitized.$set = {};

      for (const [field, value] of Object.entries(updateData)) {
        // Check if field is allowed
        if (allowedFields.length > 0 && !this.isFieldAllowed(field, allowedFields)) {
          throw new ApiError(
            HTTP_STATUS.BAD_REQUEST,
            `Field '${field}' is not allowed for updates`,
            true,
            'UNAUTHORIZED_FIELD_UPDATE'
          );
        }

        // Sanitize the value
        sanitized.$set[field] = this.sanitizeValue(value);
      }
    }

    return sanitized;
  }

  /**
   * Helper to check if a field (including dot notation) is in the allowed list
   * @param field - The field to check
   * @param allowedFields - List of allowed fields
   */
  private static isFieldAllowed(field: string, allowedFields: string[]): boolean {
    // Check exact match
    if (allowedFields.includes(field)) return true;

    // Check field path prefix match for nested fields
    const fieldParts = field.split('.');
    for (let i = 1; i <= fieldParts.length; i++) {
      const partialPath = fieldParts.slice(0, i).join('.');
      if (allowedFields.includes(partialPath)) return true;
    }

    return false;
  }

  /**
   * Safely sanitizes a value for MongoDB operations
   * @param value - The value to sanitize
   */
  private static sanitizeValue(value: any): any {
    // Handle null/undefined
    if (value === null || value === undefined) {
      return value;
    }

    // Handle primitive types
    if (typeof value !== 'object') {
      return value;
    }

    // Handle dates
    if (value instanceof Date) {
      return value;
    }

    // Handle ObjectId
    if (value instanceof Types.ObjectId) {
      return value;
    }

    // Handle arrays - recursively sanitize elements
    if (Array.isArray(value)) {
      if (value.length > this.MAX_ARRAY_LENGTH) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Array exceeds maximum allowed length (${this.MAX_ARRAY_LENGTH})`,
          true,
          'ARRAY_TOO_LARGE'
        );
      }

      return value.map(item => this.sanitizeValue(item));
    }

    // Handle objects - check for MongoDB operators
    const hasOperators = Object.keys(value).some(k => k.startsWith('$'));
    if (hasOperators) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `MongoDB operators not allowed in values`,
        true,
        'INVALID_VALUE'
      );
    }

    // Deep clone objects to prevent reference manipulation
    return JSON.parse(JSON.stringify(value));
  }

  /**
   * Recursively sanitizes MongoDB ObjectIds in nested objects and arrays
   * @param data - The data to sanitize (can be an object or array)
   * @returns The sanitized data with valid ObjectIds
   */
  static sanitizeObjectIdRecursive(data: any): any {
    // Base case: null or undefined
    if (data === null || data === undefined) {
      return data;
    }

    // Handle ObjectId strings
    if (typeof data === 'string' && Types.ObjectId.isValid(data) && data.length === 24) {
      try {
        return new Types.ObjectId(data);
      } catch (error) {
        // If conversion fails, return the original string
        return data;
      }
    }

    // Handle primitive types (not objects)
    if (typeof data !== 'object') {
      return data;
    }

    // Already an ObjectId instance
    if (data instanceof Types.ObjectId) {
      return data;
    }

    // Handle arrays - recursively sanitize each element
    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeObjectIdRecursive(item));
    }

    // Handle Date objects
    if (data instanceof Date) {
      return data;
    }

    // Handle regular objects - recursively sanitize all properties
    const sanitized: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      sanitized[key] = this.sanitizeObjectIdRecursive(value);
    }
    
    return sanitized;
  }
}