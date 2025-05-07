# Routes

The routes directory contains all API route definitions for the XcelCrowd platform. Each file represents a logical grouping of endpoints related to a specific domain entity or functionality.

## Overview

The routing system follows RESTful API principles and uses Express.js for route handling. Each route file:
- Defines HTTP endpoints (GET, POST, PUT, DELETE)
- Applies appropriate middleware for authentication and authorization
- Maps endpoints to controller methods
- Documents parameters and expected responses

## Core Route Files

| File | Description |
|------|-------------|
| `auth.routes.ts` | Authentication routes for login, registration, password reset, etc. |
| `user.routes.ts` | User profile management endpoints |
| `profile.routes.ts` | Student and company profile management |
| `challenge.routes.ts` | Challenge creation, retrieval, and management endpoints |
| `solution.routes.ts` | Student solution submission and retrieval endpoints |
| `architect.routes.ts` | Solution review and architect-specific functionality |
| `dashboard.routes.ts` | Dashboard data retrieval for different user roles |
| `ai-evaluation.routes.ts` | AI evaluation pipeline management endpoints |

## Route Structure Pattern

```typescript
// Import necessary controllers and middleware
import { Router } from 'express';
import { controller } from '../controllers/example.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { UserRole } from '../models/interfaces';

const router = Router();

/**
 * @route   GET /api/resource
 * @desc    Get all resources
 * @access  Private (Role-specific)
 */
router.get(
  '/',
  authenticate,
  authorize([UserRole.SPECIFIC_ROLE]),
  controller.getAllResources
);

/**
 * @route   POST /api/resource
 * @desc    Create a new resource
 * @access  Private (Role-specific)
 */
router.post(
  '/',
  authenticate,
  authorize([UserRole.SPECIFIC_ROLE]),
  controller.createResource
);

export default router;
```

## Route Registration

All routes are registered in the `index.ts` file, which exports a function that attaches all routes to the Express application:

```typescript
// Simplified example
import { Express } from 'express';
import authRoutes from './auth.routes';
import challengeRoutes from './challenge.routes';
// ...other route imports

export default function registerRoutes(app: Express): void {
  app.use('/api/auth', authRoutes);
  app.use('/api/challenges', challengeRoutes);
  // ...other route registrations
}
```

## Authorization Flow

1. Most routes require authentication through the `authenticate` middleware
2. Role-based authorization is applied using the `authorize([roles])` middleware
3. Resource-specific authorization may be applied through custom middleware
4. All these checks occur before the controller method is executed

## Special Routes

### AI Evaluation Routes
The `ai-evaluation.routes.ts` file contains endpoints for:
- Starting AI evaluation processes for solutions
- Checking evaluation status
- Retrieving evaluation results
- Managing the evaluation pipeline

### Architect Routes
The `architect.routes.ts` file contains endpoints for:
- Claiming solutions for review
- Submitting reviews
- Viewing solutions eligible for review

## Best Practices

- Routes only handle request routing and middleware application
- Business logic is delegated to controllers and services
- Route parameters are validated using validation middleware
- Routes are documented with descriptive comments
- Authorization is applied consistently across similar resource types

## API Versioning

The API versioning is handled at the route registration level in `index.ts`. This allows for straightforward implementation of new API versions without modifying existing route files.

## Error Handling

Route errors are caught by the global error handling middleware. Individual routes do not need to implement try-catch blocks as the controllers use a `catchAsync` wrapper that forwards errors to the global error handler. 