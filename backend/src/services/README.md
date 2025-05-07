# Services

The services directory contains the business logic layer of the XcelCrowd platform. Services act as an intermediary between controllers and data models, implementing complex operations, transaction management, and domain-specific rules.

## Architecture

The service layer follows a modular architecture with strong separation of concerns:

```
services/
├── BaseService.ts          # Abstract base service with shared functionality
├── user.service.ts         # User account management
├── profile.service.ts      # Profile data operations
├── challenge.service.ts    # Challenge management
├── solution.service.ts     # Solution submission and processing
├── architect.service.ts    # Architect review functionality
├── dashboard.service.ts    # Dashboard data aggregation
├── email.service.ts        # Email notifications
├── github.service.ts       # GitHub API integration
├── ai/                     # AI evaluation subsystem
└── llm/                    # LLM service subsystem
```

## Core Design Principles

### Base Service

Most services extend the `BaseService` class, which provides:

- Transaction management through the `withTransaction()` method
- Standardized error handling
- Logging conventions
- Common utility functions
- Basic validation helpers

### Single Responsibility

Each service focuses on operations related to a specific domain entity:
- `user.service.ts` handles user authentication and account operations
- `challenge.service.ts` manages challenge creation, updates, and retrieval
- `solution.service.ts` handles student solution submissions and processing

### Transaction Management

Services implement proper transaction handling for data consistency:

```typescript
// Example transaction usage
await this.withTransaction(async (session) => {
  // Multiple database operations within a single transaction
  await ModelA.updateOne({ ... }, { session });
  await ModelB.create({ ... }, { session });
  // If any operation fails, the entire transaction is rolled back
});
```

## Key Service Components

### Challenge Service

Manages the full lifecycle of challenges:
- Challenge creation and validation
- Visibility and access control
- Deadline management
- Participant tracking
- Challenge metrics and analytics

### Solution Service

Handles student solution submissions:
- Submission validation and storage
- Integration with GitHub API
- Triggering AI evaluation pipeline
- Solution review management
- Solution status updates

### Architect Service

Manages architect review workflows:
- Solution assignment and claiming
- Review submission
- Quality assurance
- Company recommendation
- Performance metrics

### Dashboard Service

Aggregates data for user dashboards:
- Role-specific dashboard data
- Performance metrics
- Activity feeds
- Recommendation engines

### GitHub Service

Provides integration with GitHub repositories:
- Repository validation
- Code retrieval and analysis
- Structure analysis
- Commit history inspection
- Token management for API rate limits

## Specialized Subsystems

### AI Evaluation System

The `ai/` subdirectory contains a sophisticated multi-agent system for evaluating student submissions:
- Sequential evaluation pipeline
- Specialized evaluation agents
- LLM-powered analysis
- See [AI README](./ai/README.md) for details

### LLM Service

The `llm/` subdirectory implements a robust framework for interacting with Large Language Models:
- Provider abstraction (OpenAI, Anthropic, Azure)
- Caching and optimization
- Token management
- See [LLM README](./llm/README.md) for details

## Best Practices

### Data Validation

Services implement thorough validation:

```typescript
// Example validation in a service method
if (!data.title || typeof data.title !== 'string') {
  throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Title is required and must be a string');
}

// Sanitize all string inputs
const sanitizedTitle = MongoSanitizer.sanitizeString(data.title.trim());
```

### Error Handling

Consistent error management with the `ApiError` class:

```typescript
throw new ApiError(
  HTTP_STATUS.NOT_FOUND,
  'Challenge not found',
  true,  // Is operational (expected) error
  'CHALLENGE_NOT_FOUND' // Error code
);
```

### Logging

Comprehensive logging for observability:

```typescript
logger.info(`Student ${studentId} submitted solution for challenge ${challengeId}`, {
  studentId,
  challengeId,
  solutionId: solution._id
});
```

## Security Considerations

The service layer implements several security measures:
- Input sanitization to prevent NoSQL injection
- Authorization checks
- Data validation
- Rate limiting for sensitive operations
- Secure handling of GitHub tokens

## Integration Points

Services integrate with various system components:
- Database models for data persistence
- External APIs (GitHub, email providers)
- AI evaluation pipeline
- LLM providers
- File storage systems

## Usage Example

```typescript
// In a controller
export const createChallenge = catchAsync(async (req: AuthRequest, res: Response) => {
  const challengeData = req.body;
  const companyId = req.user!.userId;
  
  const challenge = await challengeService.createChallenge(companyId, challengeData);
  
  res.status(HTTP_STATUS.CREATED).json({
    success: true,
    data: challenge
  });
});

// In the service
public async createChallenge(companyId: string, challengeData: ChallengeCreationData): Promise<IChallenge> {
  // Validate inputs
  // Sanitize data
  // Perform business logic
  // Persist to database
  // Return result
}
``` 