/**
 * HTTP status codes
 */
export const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    UNPROCESSABLE_ENTITY: 422,
    INTERNAL_SERVER_ERROR: 500
  };
  
  /**
   * Environment constants
   */
  export const ENV = {
    DEVELOPMENT: 'development',
    PRODUCTION: 'production',
    TEST: 'test'
  };
  
  /**
   * Security constants
   */
  export const SECURITY = {
    JWT_EXPIRATION: '1d',
    PASSWORD_SALT_ROUNDS: 10,
    PASSWORD_MIN_LENGTH: 8
  };