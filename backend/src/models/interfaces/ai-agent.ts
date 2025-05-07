import { Document, Types } from 'mongoose';
import { ISolution } from '.';

/**
 * Standard evaluation response status values
 */
export enum EvaluationResponseStatus {
  SUCCESS = 'success',
  ERROR = 'error',
  WARNING = 'warning'
}

/**
 * Standard evaluation decision values
 */
export enum EvaluationDecision {
  PASS = 'pass',           // Meets criteria to continue to next step
  FAIL = 'fail',           // Does not meet criteria, should stop evaluation
  REVIEW = 'review'        // Requires manual review
}

/**
 * Standardized evaluation response wrapper
 * All agent results should follow this format for consistency
 */
export interface IStandardizedEvaluationResponse<T extends IAgentEvaluationResult> {
  success: boolean;                  // Whether the evaluation completed successfully
  status: EvaluationResponseStatus;  // Status of the response
  message: string;                   // Human-readable message
  decision: EvaluationDecision;      // Decision that affects workflow
  result: T;                         // The detailed evaluation result
  processingTimeMs?: number;         // The time taken to process this evaluation
  traceId?: string;                  // For request tracing across systems
}

/**
 * Base interface for all evaluation agent results
 */
export interface IAgentEvaluationResult {
  score: number;  // Numerical assessment (0-100)
  feedback: string;  // Detailed feedback
  metadata: Record<string, any>;  // Additional agent-specific metrics
  evaluatedAt: Date;  // Timestamp of the evaluation
}

/**
 * Spam/Bad Submission Filtering Agent result
 */
export interface ISpamFilteringResult extends IAgentEvaluationResult {
  metadata: {
    isSpam: boolean;  // Whether the submission is identified as spam
    isValid: boolean;  // Whether the submission is valid (has proper content)
    repositoryExists: boolean;  // Whether the GitHub repository exists
    repositoryAccessible: boolean;  // Whether the GitHub repository is accessible
    confidence: number;  // Confidence level in spam detection (0-100)
    spamIndicators: string[];  // Indicators of spam if detected
    validationErrors: string[];  // Validation errors if any
  };
}

/**
 * Requirements Compliance Agent result
 */
export interface IRequirementsComplianceResult extends IAgentEvaluationResult {
  metadata: {
    requirementsSatisfied: number;  // Number of requirements met
    totalRequirements: number;  // Total requirements to check
    missingRequirements: string[];  // List of requirements not satisfied
    formatErrors?: string[];  // Any format validation issues
    repositoryStructure: {  // Structure of the GitHub repository
      hasRequiredFiles: boolean;
      missingFiles: string[];
      hasReadme: boolean;
      hasProperStructure: boolean;
    };
  };
}

/**
 * Code Quality Agent result
 */
export interface ICodeQualityResult extends IAgentEvaluationResult {
  metadata: {
    codeStyle: number;  // Code style score (0-100)
    security: number;  // Security score (0-100)
    performance: number;  // Performance score (0-100)
    maintainability: number;  // Maintainability score (0-100)
    vulnerabilities: Array<{
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      location?: string;
    }>;
    improvementAreas: string[];  // Specific areas to improve
    codeMetrics: {
      linesOfCode: number;
      complexity: number;
      duplication: number;
      testCoverage?: number;
    };
    repoStats: {
      commitCount: number;
      contributorCount: number;
      branchCount: number;
    };
    // LLM analysis results
    llmAnalysis?: {
      fileAnalysis?: Record<string, any>;
      architectureAnalysis?: {
        architectureScore: number;
        designPatterns: string[];
        architectureRecommendations: string[];
        strengths: string[];
        weaknesses: string[];
      } | null;
      enhancedVulnerabilities?: boolean;
    };
  };
}

/**
 * Scoring and Feedback Agent result
 */
export interface IScoringFeedbackResult extends IAgentEvaluationResult {
  metadata: {
    componentScores: {
      spamFilter: number;  // Spam filter score (0-100)
      requirements: number;  // Requirements compliance score (0-100)
      codeQuality: number;  // Code quality score (0-100)
    };
    weightedScore: number;  // Final weighted score (0-100)
    confidence: number;  // Confidence in evaluation (0-100)
    humanReviewRecommended: boolean;  // Whether human review is recommended
    strengths: string[];  // Areas where solution excels
    weaknesses: string[];  // Areas where solution needs improvement
    suggestedFeedback: string;  // Suggested feedback for the student
    suggestedArchitects: Array<{  // Suggested architects for review
      architectId: Types.ObjectId;
      matchScore: number;  // Match score (0-100)
      expertise: string[];  // Relevant expertise areas
    }>;
    priorityLevel: 'low' | 'medium' | 'high';  // Priority for review
  };
}

/**
 * Combined AI evaluation result stored in database
 */
export interface IAIEvaluation extends Document {
  solution: Types.ObjectId | ISolution;  // Reference to the solution
  spamFiltering?: ISpamFilteringResult;  // Spam filtering result
  requirementsCompliance?: IRequirementsComplianceResult;  // Requirements compliance result
  codeQuality?: ICodeQualityResult;  // Code quality result
  scoringFeedback?: IScoringFeedbackResult;  // Scoring and feedback result
  status: 'pending' | 'in_progress' | 'completed' | 'failed';  // Status of the evaluation
  createdAt: Date;  // When the evaluation was created
  updatedAt: Date;  // When the evaluation was last updated
  completedAt?: Date;  // When the evaluation was completed
  failureReason?: string;  // Reason for failure if status is 'failed'
  retryCount?: number; // Number of retry attempts for the evaluation
  metadata?: Record<string, any>;  // Additional metadata for the evaluation
}

/**
 * Base interface for all evaluation agents
 */
export interface IEvaluationAgent<T extends IAgentEvaluationResult> {
  evaluate(solution: ISolution): Promise<IStandardizedEvaluationResponse<T>>;
  name: string;
  description: string;
}