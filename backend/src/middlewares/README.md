# Authorization System

This directory contains various middleware functions used for authentication, authorization, and security in the application.

## Student-Only Platform

XcelCrowd is a student-only platform. Access to all resources (challenges, solutions, profiles, etc.) is restricted to authenticated students only. This is enforced using the `studentOnlyPlatform` middleware, which restricts all non-authentication endpoints to authenticated users.

> **Note**: University email validation will be implemented in the future to verify student status. This will ensure that only individuals with valid university email addresses can register and access the platform.

## Authentication Middleware

Authentication is handled by the `authenticate` middleware which verifies the presence and validity of JWT tokens.
It extracts tokens from:
- HTTP-only cookies (primary method)
- Authorization header (fallback method)

## Authorization Middleware

The system uses multiple levels of authorization:

### 1. Role-Based Authorization

The `authorize([UserRole.X])` middleware restricts access to routes based on user roles:
- **STUDENT**: Can submit solutions, view their own solutions
- **COMPANY**: Can create/manage challenges, view solutions to their challenges
- **ARCHITECT**: Can review solutions, select top performers
- **ADMIN**: Has full system access

Example usage:
```typescript
router.post(
  '/challenges',
  authenticate,
  authorize([UserRole.COMPANY]),
  createChallenge
);
```

### 2. Institution-Based Authorization

For private challenges, the `authorizeInstitutionForChallenge()` middleware provides institution-specific access control:

- Verifies if a student's university/institution matches the `allowedInstitutions` list of a private challenge
- Centralizes access control logic in a single place
- Automatically skips verification for non-STUDENT users and non-private challenges

Example usage:
```typescript
router.get(
  '/challenges/:id',
  authenticate,
  authorizeInstitutionForChallenge(),
  getChallengeById
);
```

For POST routes where the challenge ID is in the request body rather than params:
```typescript
router.post(
  '/solutions',
  authenticate,
  authorize([UserRole.STUDENT]),
  (req, res, next) => {
    if (req.body && req.body.challenge) {
      req.params.challengeId = req.body.challenge;
      return authorizeInstitutionForChallenge('challengeId')(req, res, next);
    }
    next();
  },
  submitSolution
);
```

## Security Middleware

Additional security middleware includes:
- CSRF protection
- Rate limiting for login attempts
- XSS prevention

## Implementation Notes

- The institution-based authorization middleware uses dynamic imports to avoid circular dependencies
- All authorization failures are properly logged for security auditing
- Authorization checks happen early in the request pipeline to prevent unnecessary processing
- The student-only platform middleware is applied globally to restrict all public access 