import { 
  IAgentEvaluationResult, 
  IEvaluationAgent, 
  ISolution,
  IStandardizedEvaluationResponse,
  EvaluationResponseStatus,
  EvaluationDecision
} from '../../models/interfaces';
import { logger } from '../../utils/logger';
import { ApiError } from '../../utils/api.error';
import { HTTP_STATUS } from '../../models/interfaces';
import { v4 as uuidv4 } from 'uuid';

/**
 * Abstract base class for all AI evaluation agents
 * Implements common functionality and enforces required patterns
 */
export abstract class AIAgentBase<T extends IAgentEvaluationResult> implements IEvaluationAgent<T> {
  public abstract name: string;
  public abstract description: string;
  
  /**
   * Evaluate a solution using AI
   * This is the main method that all agents must implement
   * @param solution - The solution to evaluate
   */
  public abstract evaluateInternal(solution: ISolution): Promise<T>;
  
  /**
   * Determine the evaluation decision based on the result
   * Override this in derived classes for agent-specific decision logic
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or request review
   */
  protected determineDecision(result: T): EvaluationDecision {
    // Default implementation based on score
    // Derived classes should override this for more nuanced decisions
    if (result.score >= 70) {
      return EvaluationDecision.PASS;
    } else if (result.score >= 30) {
      return EvaluationDecision.REVIEW;
    } else {
      return EvaluationDecision.FAIL;
    }
  }
  
  /**
   * Public evaluate method with error handling and logging
   * @param solution - The solution to evaluate
   */
  public async evaluate(solution: ISolution): Promise<IStandardizedEvaluationResponse<T>> {
    const traceId = uuidv4();
    const startTime = Date.now();
    
    try {
      logger.debug(`Starting ${this.name} evaluation`, {
        agent: this.name,
        solutionId: solution._id?.toString(),
        traceId,
        challengeId: (solution.challenge && typeof solution.challenge === 'object' && '_id' in solution.challenge)
          ? (solution.challenge as { _id?: any })._id?.toString()
          : (solution.challenge ? String(solution.challenge) : undefined)
      });
      
      // Validate solution has required fields for evaluation
      this.validateSolution(solution);
      
      // Perform the actual evaluation
      const result = await this.evaluateInternal(solution);
      const duration = Date.now() - startTime;
      
      // Set evaluation timestamp
      result.evaluatedAt = new Date();
      
      // Determine decision
      const decision = this.determineDecision(result);
      
      logger.info(`Completed ${this.name} evaluation`, {
        agent: this.name,
        solutionId: solution._id?.toString(),
        traceId,
        score: result.score,
        decision,
        durationMs: duration
      });
      
      // Return standardized response
      return {
        success: true,
        status: EvaluationResponseStatus.SUCCESS,
        message: `${this.name} evaluation completed successfully`,
        decision,
        result,
        processingTimeMs: duration,
        traceId
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.error(`Error in ${this.name} evaluation`, {
        agent: this.name,
        solutionId: solution._id?.toString(),
        traceId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        durationMs: duration
      });
      
      // Create a error response
      const errorResponse: IStandardizedEvaluationResponse<T> = {
        success: false,
        status: EvaluationResponseStatus.ERROR,
        message: `${this.name} evaluation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        decision: EvaluationDecision.FAIL, // Default to fail on error
        result: ({
          score: 0,
          feedback: `Evaluation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
          metadata: { error: error instanceof Error ? error.message : String(error) },
          evaluatedAt: new Date()
        } as unknown) as T,
        processingTimeMs: duration,
        traceId
      };
      
      // If it's an API error, just return the error response
      if (error instanceof ApiError) {
        return errorResponse;
      }
      
      // For other errors, wrap in ApiError and throw
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        `AI evaluation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        true,
        'AI_EVALUATION_ERROR'
      );
    }
  }
  
  /**
   * Validate that the solution has all required fields for evaluation
   * @param solution - The solution to validate
   * @throws ApiError if the solution is invalid
   */
  protected validateSolution(solution: ISolution): void {
    if (!solution) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution is required for evaluation',
        true,
        'INVALID_SOLUTION'
      );
    }
    
    if (!solution._id) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution ID is required for evaluation',
        true,
        'INVALID_SOLUTION_ID'
      );
    }
    
    if (!solution.submissionUrl) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Solution must have a submission URL for evaluation',
        true,
        'MISSING_SUBMISSION_URL'
      );
    }
    
    // Additional validation can be implemented in derived classes
  }
} 