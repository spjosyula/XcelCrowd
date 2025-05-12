/**
 * HTTP status codes
 */
export const HTTP_STATUS = {
  OK: 200,  // Request succeeded
  CREATED: 201,  // Resource successfully created
  BAD_REQUEST: 400,  // Invalid request syntax or parameters
  TOO_MANY_REQUESTS: 429,  // Too many requests in a given time frame
  UNAUTHORIZED: 401,  // Authentication required or failed
  FORBIDDEN: 403,  // User doesn't have permission for the requested action
  NOT_FOUND: 404,  // Resource not found
  CONFLICT: 409,  // Request conflicts with current state of the server
  UNPROCESSABLE_ENTITY: 422,  // Request understood but semantically incorrect
  INTERNAL_SERVER_ERROR: 500,  // Server encountered an unexpected error
  GATEWAY_TIMEOUT: 504,  // Server didn't receive a timely response from upstream server 
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