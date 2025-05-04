# Controller Best Practices

This document outlines the standard patterns for authorization, error handling, and logging that should be followed in all controllers.

## Authorization Patterns

All controllers should extend `BaseController` and use its authorization methods:

1. **Basic Authorization**:
   ```typescript
   // Check authentication and optionally role
   this.verifyAuthorization(req, [UserRole.STUDENT], 'performing this action');
   ```

2. **Getting Profile IDs**:
   ```typescript
   // Get profile ID for role-specific actions
   const profileId = await this.getUserProfileId(req, UserRole.COMPANY);
   ```

3. **Resource Ownership**:
   ```typescript
   // Verify resource ownership
   await this.verifyResourceOwnership(req, resource, 'company', UserRole.COMPANY);
   ```

4. **Comprehensive Checks**:
   ```typescript
   // Combined role and ownership check
   await this.authorize(req, {
     allowedRoles: [UserRole.COMPANY, UserRole.ADMIN],
     resource: challenge,
     ownerIdField: 'company',
     ownerRole: UserRole.COMPANY,
     failureMessage: 'You do not have permission to access this challenge'
   });
   ```

## Error Handling

All controller methods should:

1. Use the `catchAsync` wrapper for consistent error handling
2. Throw standardized `ApiError` instances with appropriate status codes
3. Log errors appropriately
4. Avoid try/catch blocks within controller methods when possible

## Logging

All controller methods should log important actions:

```typescript
// Log actions with consistent format
this.logAction('action-name', req.user!.userId, {
  resourceId: id,
  additionalInfo: 'value'
});
```

## Response Format

Use standardized response methods:

1. **Regular responses**:
   ```typescript
   this.sendSuccess(res, data, 'Operation successful', HTTP_STATUS.OK);
   ```

2. **Paginated responses**:
   ```typescript
   this.sendPaginatedSuccess(res, paginationResult, 'Items retrieved successfully');
   ```

## Code Organization

1. Controllers should delegate business logic to services
2. Controllers should handle:
   - Request validation
   - Authorization
   - HTTP response formatting
   - Logging

## Validation

1. Use `MongoSanitizer.validateObjectId` for MongoDB ID validation
2. Delegate complex validation to services

## Authorization Levels

Here are common authorization patterns:

1. **Public**: No authorization required
2. **Authenticated**: Just requires a valid user
3. **Role-based**: Requires specific user role(s)
4. **Owner**: Requires resource ownership
5. **Admin**: Admin override for most resources 