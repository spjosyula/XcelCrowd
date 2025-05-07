# AI Evaluation System

The AI directory implements a sophisticated multi-agent evaluation pipeline for automatically assessing student solution submissions. This enterprise-grade system uses a sequence of specialized AI agents to perform comprehensive evaluations with progressive filtering.

## Architecture Overview

The system follows a modular architecture based on the Chain of Responsibility and Strategy patterns:

```
ai/
├── agents/                      # Specialized evaluation agents
│   ├── SpamFilteringAgent.ts    # First-pass filtering for spam/invalid submissions
│   ├── RequirementsComplianceAgent.ts # Verifies challenge requirements are met
│   ├── CodeQualityAgent.ts      # Analyzes code quality metrics
│   └── ScoringFeedbackAgent.ts  # Generates final scores and feedback
├── AIAgentBase.ts               # Abstract base class for all agents
├── AIAgentFactory.ts            # Factory for agent instantiation
├── EvaluationPipelineController.ts # Orchestrates the evaluation workflow
├── ai-evaluation.service.ts     # Service layer API for evaluation
└── index.ts                     # Exports and initialization
```

## Core Components

### Agent Base Class

The `AIAgentBase` abstract class provides common functionality for all agents:
- Standard error handling and validation
- Decision determination logic
- Result formatting and standardization
- Logging and tracing

### Agent Factory

The `AIAgentFactory` implements a singleton factory pattern for agent management:
- Lazy initialization of agent instances
- Agent registration and retrieval
- Verification of agent availability

### Evaluation Pipeline Controller

The `EvaluationPipelineController` orchestrates the entire evaluation workflow:
- Manages the sequential execution of agents
- Handles decision flow control between agents
- Aggregates and processes results from each agent
- Implements retry and recovery strategies
- Prepares final evaluation results for architects

### AI Evaluation Service

The `ai-evaluation.service.ts` provides the service layer API:
- Exposes methods to start, monitor, and retrieve evaluations
- Manages database persistence of evaluation results
- Implements transaction handling and concurrency control
- Provides status reporting and analytics

## Agent Workflow

The evaluation process follows a sequential pipeline with decision points:

1. **Submission Processing**
   - When the challenge deadline passes, solutions become locked
   - Submissions are queued for AI evaluation

2. **Spam Filtering Agent**
   - First agent in the pipeline validates GitHub repository
   - Checks for spam, empty repositories, or irrelevant content
   - Rejects clearly invalid submissions with feedback
   - Passes legitimate submissions to the next stage

3. **Requirements Compliance Agent**
   - Analyzes if submission meets challenge requirements
   - Uses rule-based checks and LLM-based deep analysis
   - Can reject submissions missing critical requirements
   - Passes compliant submissions to the next stage

4. **Code Quality Agent**
   - Analyzes code quality metrics (style, security, performance)
   - Identifies vulnerabilities and areas for improvement
   - Does not reject but provides comprehensive analysis
   - Passes all submissions with quality metrics to the next stage

5. **Scoring and Feedback Agent**
   - Integrates results from all previous agents
   - Generates final score and personalized feedback
   - Recommends matching architects for review
   - Determines submission priority

6. **Final Processing**
   - High-scoring submissions are sent to architects for review
   - Low-scoring submissions can be automatically rejected
   - Students receive feedback on their dashboard
   - Architects perform final review before sending to companies

## Singleton Pattern Implementation

All agents follow a consistent singleton pattern:
- Each agent class has a private static instance property
- A private constructor prevents direct instantiation
- A public static getInstance() method provides access to the singleton instance
- An exported constant provides convenient access to each agent instance

Example:
```typescript
export class SomeAgent extends AIAgentBase<ISomeResult> {
  private static instance: SomeAgent;
  
  private constructor() {
    super();
    // Initialization logic
  }
  
  public static getInstance(): SomeAgent {
    if (!SomeAgent.instance) {
      SomeAgent.instance = new SomeAgent();
    }
    return SomeAgent.instance;
  }
  
  // Agent implementation
}

// Export singleton instance
export const someAgent = SomeAgent.getInstance();
```

## Decision Logic

Agents make decisions about submissions using the EvaluationDecision enum:
- **PASS**: Submission meets criteria and should proceed to the next stage
- **FAIL**: Submission does not meet criteria and should be rejected
- **REVIEW**: Submission needs manual review by an architect

The pipeline controller respects these decisions:
- FAIL at any stage typically results in rejection
- REVIEW triggers architect involvement
- All decisions are recorded with justifications

## LLM Integration

Agents leverage the LLM service for advanced analysis:
- Each agent uses specialized prompts for its specific evaluation area
- Structured outputs are parsed into standardized result formats
- Multiple evaluation passes may use increasingly sophisticated models
- Context from earlier agents is preserved for later agents

## Robustness Features

The system includes enterprise-grade reliability features:
- Comprehensive error handling and recovery
- Transaction support for database operations
- Retry logic for transient failures
- Rate limiting to prevent API quota exhaustion
- Detailed logging and metrics collection

## Configuration

Agent behavior is configurable through environment variables:
- LLM model selection for different evaluation stages
- Threshold values for PASS/FAIL/REVIEW decisions
- Timeout and retry settings
- Batch processing parameters for challenge-wide evaluation

## Extensibility

The system is designed for extensibility:
- New agents can be added by extending AIAgentBase
- Existing agents can be enhanced without pipeline changes
- Additional evaluation passes can be integrated by modifying the controller
- New LLM providers can be utilized through the LLM service abstraction

## Usage Example

```typescript
// Starting an evaluation for a solution
const evaluationResult = await aiEvaluationService.startEvaluation(solutionId);

// Processing all solutions for a challenge
const results = await aiEvaluationService.processChallengeForArchitectReview(challengeId);

// Getting evaluation status
const status = await aiEvaluationService.getEvaluationStatus(solutionId);
``` 