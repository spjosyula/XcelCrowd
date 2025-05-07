# Middlewares

The middlewares directory contains various Express middleware functions that handle cross-cutting concerns such as authentication, authorization, security, error handling, and request validation for the XcelCrowd platform.

## Overview

Middlewares are the backbone of the request processing pipeline, providing essential functionality:
- Authentication and authorization
- Security protection mechanisms
- Request validation
- Error handling
- Cross-origin resource sharing (CORS)
- Rate limiting

## Core Middleware Components

### Authentication Middleware (`auth.middleware.ts`)

Handles user authentication through JWT tokens:

```typescript
// Apply authentication to a route
router.get('/protected-resource', authenticate, controller.getResource);
```

Key features:
- Multiple token sources (HTTP-only cookies, Authorization header)
- Comprehensive JWT validation and error handling
- Token expiration checking
- User information attachment to request objects
- Detailed security logging

### Authorization Middleware (`auth.middleware.ts`)

Provides fine-grained access control based on:

#### 1. Role-Based Authorization

```typescript
// Restrict endpoint to specific roles
router.post('/challenges', authenticate, authorize([UserRole.COMPANY]), controller.createChallenge);
```

#### 2. Pattern-Based Authorization

```typescript
// Apply predefined authorization patterns
router.put('/solutions/:id/review', 
  authenticate, 
  authorizePattern(AuthPattern.ARCHITECT_REVIEW_SOLUTION),
  controller.reviewSolution
);
```

#### 3. Institution-Based Authorization

```typescript
// Enforce institution-specific access for private challenges
router.get('/challenges/:id',
  authenticate,
  authorizeInstitutionForChallenge(),
  controller.getChallengeById
);
```

### Security Middleware (`security.middleware.ts`)

Implements various security mechanisms:

#### 1. CSRF Protection

```typescript
// Protect mutation endpoints against CSRF attacks
router.post('/user/settings', csrfProtection, controller.updateSettings);
```

#### 2. Rate Limiting

```typescript
// Prevent brute force attacks
router.post('/login', loginRateLimiter, controller.login);
```

#### 3. Content Security Policy

Enforces restrictions on resource loading to prevent XSS and data injection attacks.

#### 4. HTTP Security Headers

Applies security headers including:
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy

### Validation Middleware (`validation.middleware.ts`)

Centralizes request validation:

```typescript
// Validate request body against a schema
router.post('/challenges', validateRequest(createChallengeSchema), controller.createChallenge);
```

Features:
- Schema-based validation using Joi or Zod
- Consistent error responses
- Extensible validation rules
- Type safety with TypeScript

### Error Handling Middleware (`errorhandler.middleware.ts`)

Global error handler that:
- Normalizes error responses
- Differentiates between operational and programming errors
- Provides detailed debugging in development
- Sanitizes error messages in production
- Logs errors appropriately
- Handles uncaught exceptions and unhandled rejections

## Implementation Patterns

### Middleware Composition

Middlewares can be composed to create reusable authorization patterns:

```typescript
// Creating a middleware stack for student-only routes
export const studentOnlyMiddleware = [
  authenticate,
  authorize([UserRole.STUDENT])
];

// Usage
router.post('/solutions', ...studentOnlyMiddleware, controller.submitSolution);
```

### Conditional Middleware Application

Middlewares that adapt based on configuration or request context:

```typescript
// Only apply rate limiting in production
const conditionalRateLimit = (req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return loginRateLimiter(req, res, next);
  }
  next();
};
```

### Dynamic Middleware Generation

Middlewares that are generated with configuration parameters:

```typescript
// Create a validation middleware for a specific schema
export const validateRequest = (schema) => (req, res, next) => {
  // Implementation that uses the schema to validate
};
```

## Key Security Features

### Authentication Workflow

1. Token extraction from cookies or header
2. JWT verification with specified algorithms
3. Expiration and signature validation
4. User object attachment to request
5. Comprehensive error handling

### Authorization Strategies

The system implements multiple authorization layers:

1. **Platform-Level**: Restricts all non-public endpoints to authenticated users
2. **Role-Level**: Restricts endpoints to specific user roles
3. **Resource-Level**: Ensures users can only access resources they own or have permission for
4. **Institution-Level**: For private challenges, ensures students are from allowed institutions

### CSRF Protection

Implemented through:
- Double-submit cookie pattern
- CSRF token verification
- SameSite cookie attributes
- HTTP-only cookie flags

### Rate Limiting

Protects against abuse with:
- IP-based limiting
- User-based limiting for authenticated users
- Sliding window algorithm
- Exponential backoff for repeated failures

## Best Practices

The middleware implementation follows several best practices:

1. **Separation of Concerns**: Each middleware handles a single responsibility
2. **DRY Principle**: Reusable middleware functions with factory patterns
3. **Configuration Over Code**: Environment variables control middleware behavior
4. **Comprehensive Logging**: All security events are properly logged
5. **Fail-Safe Defaults**: Restrictive by default, permissive by exception
6. **Type Safety**: Full TypeScript typing for request/response objects

## Middleware Execution Flow

Request processing follows this general flow:

1. **Parse Body**: Express body-parser middleware
2. **Apply Security Headers**: security.middleware.ts
3. **Authentication**: auth.middleware.ts
4. **Authorization**: auth.middleware.ts
5. **Request Validation**: validation.middleware.ts
6. **Controller Logic**: Route handler
7. **Error Handling**: errorhandler.middleware.ts (if errors occur)

## Integration Points

Middlewares integrate with various system components:

- **JWT Service**: For token verification
- **Database**: For looking up institution or resource information
- **Configuration**: For runtime behavior adjustments
- **Logging System**: For security event tracking
- **Error Handling**: For consistent error responses

## Middleware Registration

Global middlewares are registered in the application's entry point:

```typescript
// Apply global middlewares
app.use(helmet()); // Security headers
app.use(express.json()); // Body parsing
app.use(authenticatedUsersOnly()); // Platform-wide authentication
app.use(errorHandler); // Global error handling
``` 