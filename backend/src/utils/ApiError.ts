/**
 * Custom API Error class for standardized error handling
 */
export class ApiError extends Error {
  statusCode: number;
  isOperational: boolean;
  errorCode?: string;
  details?: Record<string, any>;
  
  /**
   * Create a new ApiError
   * @param statusCode HTTP status code
   * @param message Error message
   * @param isOperational Whether this is an operational error (vs programming error)
   * @param errorCode Optional error code for client identification
   * @param details Additional error details
   * @param stack Error stack trace
   */
  constructor(
    statusCode: number,
    message: string,
    isOperational = true,
    errorCode?: string,
    details?: Record<string, any>,
    stack = ''
  ) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.errorCode = errorCode;
    this.details = details;
    
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Create a Bad Request error (400)
   */
  static badRequest(message = 'Bad request', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(400, message, true, errorCode, details);
  }

  /**
   * Create an Unauthorized error (401)
   */
  static unauthorized(message = 'Unauthorized', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(401, message, true, errorCode, details);
  }

  /**
   * Create a Forbidden error (403)
   */
  static forbidden(message = 'Forbidden', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(403, message, true, errorCode, details);
  }

  /**
   * Create a Not Found error (404)
   */
  static notFound(message = 'Resource not found', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(404, message, true, errorCode, details);
  }

  /**
   * Create a Conflict error (409)
   */
  static conflict(message = 'Resource conflict', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(409, message, true, errorCode, details);
  }

  /**
   * Create a Validation error (422)
   */
  static validation(message = 'Validation failed', details?: Record<string, any>): ApiError {
    return new ApiError(422, message, true, 'VALIDATION_ERROR', details);
  }

  /**
   * Create an Internal Server Error (500)
   */
  static internal(message = 'Internal server error', errorCode?: string, details?: Record<string, any>): ApiError {
    return new ApiError(500, message, false, errorCode, details);
  }
}