import { AIAgentFactory } from './AIAgentFactory';
import { 
  ISolution, 
  IStandardizedEvaluationResponse, 
  EvaluationDecision,
  EvaluationResponseStatus,
  ISpamFilteringResult,
  IRequirementsComplianceResult,
  ICodeQualityResult,
  IScoringFeedbackResult,
  ChallengeStatus,
  ChallengeDifficulty,
  IAgentEvaluationResult
} from '../../models/interfaces';
import { logger } from '../../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { Challenge } from '../../models';
import { Types } from 'mongoose';

/**
 * Challenge context that will be shared with all agents
 * This interface aligns with the Challenge model properties
 */
export interface IChallengeContext {
  challengeId: string;
  title: string;
  description: string;
  requirements: string[];  // Original requirements from the challenge
  category?: string[];
  difficulty?: ChallengeDifficulty;
  status?: ChallengeStatus;
  deadline?: Date;
  tags?: string[];

  // Evaluation weights (not in Challenge model but used by agents)
  evaluationWeights?: {
    codeQuality: number;
    security: number;
    performance: number;
  };
  
  // Optional evaluation criteria
  evaluationCriteria?: Array<{
    criterionName: string;
    weight: number;
    description: string;
  }>;
  
  // Additional metadata
  metadata?: Record<string, any>;
}

/**
 * Result of a complete pipeline evaluation
 * The interface uses intersection types to allow both string indexing and specific typed properties
 * This resolves TypeScript errors while maintaining type safety
 */
export interface IPipelineResult {
  success: boolean;
  pipelineCompleted: boolean;
  stoppedAt?: string;
  reason?: string;
  results: {
    [key: string]: IStandardizedEvaluationResponse<IAgentEvaluationResult>;
  } & {
    spamFiltering?: IStandardizedEvaluationResponse<ISpamFilteringResult>;
    requirementsCompliance?: IStandardizedEvaluationResponse<IRequirementsComplianceResult>;
    codeQuality?: IStandardizedEvaluationResponse<ICodeQualityResult>;
    scoringFeedback?: IStandardizedEvaluationResponse<IScoringFeedbackResult>;
    // New agent naming convention (agent name with Agent suffix)
    SpamFilteringAgent?: IStandardizedEvaluationResponse<ISpamFilteringResult>;
    RequirementsComplianceAgent?: IStandardizedEvaluationResponse<IRequirementsComplianceResult>;
    CodeQualityAgent?: IStandardizedEvaluationResponse<ICodeQualityResult>;
    ScoringFeedbackAgent?: IStandardizedEvaluationResponse<IScoringFeedbackResult>;
  };
  finalDecision: EvaluationDecision;
  processingTimeMs: number;
  traceId: string;
  challengeContext?: IChallengeContext;
}

/**
 * A controller that orchestrates the evaluation pipeline by executing agents in sequence
 * Manages the flow control and decision logic between agents
 * Provides a clean API for starting and monitoring evaluation
 */
export class EvaluationPipelineController {
  private static instance: EvaluationPipelineController;
  private readonly agentFactory: AIAgentFactory;
  
  // Define the evaluation pipeline stages and their execution order
  private readonly PIPELINE_STAGES = [
    'SpamFilteringAgent',
    'RequirementsComplianceAgent',
    'CodeQualityAgent',
    'ScoringFeedbackAgent'
  ];
  
  // Define which stages can reject submissions
  private readonly REJECTION_ENABLED_STAGES = [
    'SpamFilteringAgent',
    'RequirementsComplianceAgent'
  ];
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    this.agentFactory = AIAgentFactory.getInstance();
  }
  
  /**
   * Get the singleton instance
   * @returns The controller instance
   */
  public static getInstance(): EvaluationPipelineController {
    if (!EvaluationPipelineController.instance) {
      EvaluationPipelineController.instance = new EvaluationPipelineController();
    }
    return EvaluationPipelineController.instance;
  }
  
  /**
   * Analyze challenge details to create a comprehensive context for all agents
   * @param challengeId - The ID of the challenge
   * @returns Structured challenge context
   */
  private async analyzeChallengeContext(challengeId: string): Promise<IChallengeContext> {
    try {
      logger.info(`Analyzing challenge context for challengeId: ${challengeId}`);
      
      // Load challenge details from database
      const challenge = await Challenge.findById(challengeId);
      
      if (!challenge) {
        logger.error(`Challenge not found for ID: ${challengeId}`);
        throw new Error(`Challenge not found for ID: ${challengeId}`);
      }
      
      // Create comprehensive challenge context
      const challengeContext: IChallengeContext = {
        challengeId: (challenge._id as Types.ObjectId).toString(),
        title: challenge.title,
        description: challenge.description,
        requirements: challenge.requirements || [],
        category: challenge.category,
        difficulty: challenge.difficulty,
        status: challenge.status,
        deadline: challenge.deadline,
        tags: challenge.tags,
        evaluationWeights: {
          codeQuality: 0.5,
          security: 0.3,
          performance: 0.2
        },
        evaluationCriteria: [], // Initialize with empty array since it's not in the model
        metadata: {
          company: challenge.company,
          resources: challenge.resources,
          rewards: challenge.rewards,
          maxParticipants: challenge.maxParticipants,
          currentParticipants: challenge.currentParticipants,
          completedAt: challenge.completedAt,
          publishedAt: challenge.publishedAt,
          visibility: challenge.visibility,
          allowedInstitutions: challenge.allowedInstitutions,
          isCompanyVisible: challenge.isCompanyVisible
        }
      };
      
      logger.info(`Challenge context analysis completed`, {
        challengeId
      });
      
      return challengeContext;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error analyzing challenge context`, {
        challengeId,
        error: errorMessage
      });
      
      // Return minimal context with empty requirements in case of error
      return {
        challengeId,
        title: 'Unknown Challenge',
        description: 'Unable to retrieve challenge details',
        requirements: [],
      };
    }
  }
  
  
  /**
   * Execute the complete evaluation pipeline for a solution
   * @param solution - The solution to evaluate
   * @returns Result of the pipeline execution
   */
  public async executePipeline(solution: ISolution): Promise<IPipelineResult> {
    const traceId = uuidv4();
    const startTime = Date.now();
    
    // Store results from each stage
    const results: IPipelineResult['results'] = {};
    
    // Circuit breaker state
    const circuitBreakers: Record<string, {
      failures: number;
      lastFailure: number;
      isOpen: boolean;
    }> = {};
    
    // Initialize circuit breakers for each agent
    for (const stageName of this.PIPELINE_STAGES) {
      circuitBreakers[stageName] = {
        failures: 0,
        lastFailure: 0,
        isOpen: false
      };
    }
    
    try {
      logger.info(`Starting evaluation pipeline for solution`, {
        solutionId: solution._id?.toString(),
        challengeId: solution.challenge?.toString(),
        traceId
      });
      
      // Analyze challenge context first
      let challengeContext: IChallengeContext | undefined = undefined;
      if (solution.challenge) {
        challengeContext = await this.analyzeChallengeContext(solution.challenge.toString());
      }
      
      // Initialize solution context if it doesn't exist
      if (!solution.context) {
        solution.context = {
          evaluationId: traceId,
          pipelineResults: {}
        };
      }
      
      // Store challenge context in solution context
      if (challengeContext) {
        solution.context.challengeContext = challengeContext;
      }
      
      // Execute each stage in sequence with circuit breaker protection
      for (const stageName of this.PIPELINE_STAGES) {
        try {
          // Check if circuit breaker is open
          const breaker = circuitBreakers[stageName];
          if (breaker.isOpen) {
            const now = Date.now();
            const timeElapsed = now - breaker.lastFailure;
            
            // Use exponential backoff based on failure count
            const backoffTime = Math.min(
              30000, // Max 30 seconds
              Math.pow(2, breaker.failures) * 1000 // Exponential backoff
            );
            
            if (timeElapsed < backoffTime) {
              logger.warn(`Circuit breaker open for ${stageName}`, {
                solutionId: solution._id?.toString(),
                traceId,
                backoffTimeMs: backoffTime,
                timeElapsedMs: timeElapsed
              });
              
              // Skip this stage and set status in result
              results[stageName] = {
                success: false,
                status: EvaluationResponseStatus.ERROR,
                message: `${stageName} evaluation skipped due to circuit breaker`,
                decision: EvaluationDecision.FAIL,
                result: {
                  score: 0,
                  feedback: `Evaluation skipped due to service protection (circuit breaker open)`,
                  metadata: { circuitBreakerOpen: true },
                  evaluatedAt: new Date()
                } as any,
                processingTimeMs: 0,
                traceId
              };
              
              continue;
            }
            
            // Reset circuit breaker after backoff time
            breaker.isOpen = false;
          }
          
          // Get the agent instance
          const agent = this.agentFactory.getAgent(stageName);
          
          // Collect all previous results for context
          const previousResults = this.collectPreviousResults(results);
          
          // Log the stage start
          logger.debug(`Starting ${stageName} evaluation`, {
            solutionId: solution._id?.toString(),
            traceId,
            stage: stageName
          });
          
          // Give the agent enhanced context about the challenge and previous evaluations
          // This helps the AI better understand the challenge requirements and build on previous analysis
          if (solution.context) {
            solution.context.currentStage = stageName;
            solution.context.previousResults = previousResults;
          }
          
          // Execute the agent
          const result = await agent.evaluate(solution, previousResults);
          
          // Store the result
          results[stageName] = result;
          
          // Store the result in solution context
          if (solution.context && solution.context.pipelineResults) {
            solution.context.pipelineResults[stageName] = result;
          }
          
          // Check if we should reject the solution at this stage
          if (
            (result.decision === EvaluationDecision.FAIL || result.decision === EvaluationDecision.ERROR) &&
            this.REJECTION_ENABLED_STAGES.includes(stageName)
          ) {
            logger.info(`Solution rejected at ${stageName} stage`, {
              solutionId: solution._id?.toString(),
              traceId,
              stage: stageName,
              decision: result.decision,
              score: result.result.score
            });
            
            // Break the pipeline if this stage rejected the solution
            return {
              success: false,
              pipelineCompleted: false,
              stoppedAt: stageName,
              reason: `Rejected at ${stageName} stage: ${result.message}`,
              results,
              finalDecision: result.decision,
              processingTimeMs: Date.now() - startTime,
              traceId,
              challengeContext: solution.context?.challengeContext
            };
          }
          
          // Reset circuit breaker on success
          circuitBreakers[stageName].failures = 0;
          
          // Log the stage completion
          logger.debug(`Completed ${stageName} evaluation`, {
            solutionId: solution._id?.toString(),
            traceId,
            stage: stageName,
            decision: result.decision,
            score: result.result.score,
            processingTimeMs: result.processingTimeMs
          });
        } catch (error) {
          // Log the error
          logger.error(`Error in ${stageName} evaluation`, {
            solutionId: solution._id?.toString(),
            traceId,
            stage: stageName,
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined
          });
          
          // Update circuit breaker
          const breaker = circuitBreakers[stageName];
          breaker.failures++;
          breaker.lastFailure = Date.now();
          
          // Open circuit breaker if too many failures
          if (breaker.failures >= 3) {
            breaker.isOpen = true;
            logger.warn(`Circuit breaker opened for ${stageName}`, {
              solutionId: solution._id?.toString(),
              traceId,
              stage: stageName,
              failures: breaker.failures
            });
          }
          
          // Create an error result
          const errorResult: IStandardizedEvaluationResponse<any> = {
            success: false,
            status: EvaluationResponseStatus.ERROR,
            message: `${stageName} evaluation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            decision: EvaluationDecision.ERROR,
            result: {
              score: 0,
              feedback: `Evaluation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
              metadata: { error: error instanceof Error ? error.message : String(error) },
              evaluatedAt: new Date()
            },
            processingTimeMs: 0,
            traceId
          };
          
          // Store the error result
          results[stageName] = errorResult;
          
          // Store the error result in solution context
          if (solution.context && solution.context.pipelineResults) {
            solution.context.pipelineResults[stageName] = errorResult;
          }
          
          // Continue to next stage instead of failing completely
          continue;
        }
      }
      
      // Determine the final decision based on all results
      const finalDecision = this.determineFinalDecision(results);
      
      // Calculate total processing time
      const processingTimeMs = Date.now() - startTime;
      
      logger.info(`Completed evaluation pipeline for solution`, {
        solutionId: solution._id?.toString(),
        traceId,
        finalDecision,
        processingTimeMs,
        stagesCompleted: Object.keys(results).length,
        totalStages: this.PIPELINE_STAGES.length
      });
      
      // Return the pipeline result
      return {
        success: true,
        pipelineCompleted: true,
        results,
        finalDecision,
        processingTimeMs,
        traceId,
        challengeContext: solution.context?.challengeContext
      };
    } catch (error) {
      // Calculate processing time even for error case
      const processingTimeMs = Date.now() - startTime;
      
      logger.error(`Error in evaluation pipeline`, {
        solutionId: solution._id?.toString(),
        traceId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        processingTimeMs
      });
      
      // Return error result
      return {
        success: false,
        pipelineCompleted: false,
        stoppedAt: 'pipeline_controller',
        reason: `Evaluation pipeline error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        results,
        finalDecision: EvaluationDecision.ERROR,
        processingTimeMs,
        traceId,
        challengeContext: solution.context?.challengeContext
      };
    }
  }
  
  /**
   * Collect previous agent results for passing to next stage
   * @param results - Current pipeline results
   * @returns Previous results for next agent
   */
  private collectPreviousResults(
    results: IPipelineResult['results']
  ): Record<string, IAgentEvaluationResult> {
    const previousResults: Record<string, IAgentEvaluationResult> = {};
    
    // Convert from pipeline results structure to flat structure for agents
    for (const [key, value] of Object.entries(results)) {
      if (value?.success && value?.result) {
        previousResults[key] = value.result;
      }
    }
    
    return previousResults;
  }
  
  /**
   * Determine the final decision based on all stage results
   * @param results - The results from all pipeline stages
   * @returns The final decision for the solution
   */
  private determineFinalDecision(results: IPipelineResult['results']): EvaluationDecision {
    // If ScoringFeedbackAgent ran, use its decision
    if (results.ScoringFeedbackAgent) {
      return results.ScoringFeedbackAgent.decision;
    }
    
    // If scoring feedback isn't available but we have an older format key, use that
    if (results.scoringFeedback) {
      return results.scoringFeedback.decision;
    }
    
    // If any stage had a REVIEW decision, the final decision is REVIEW
    if (Object.values(results).some(result => result?.decision === EvaluationDecision.REVIEW)) {
      return EvaluationDecision.REVIEW;
    }
    
    // Default to PASS if all stages passed
    return EvaluationDecision.PASS;
  }
  
  /**
   * Get metrics about agent results
   * @param results - The results from all pipeline stages
   * @returns Object with aggregated metrics
   */
  public getMetricsFromResults(results: IPipelineResult['results']): {
    averageScore: number; // Average score across all stages
    scores: Record<string, number>; // Individual scores from each stage
    stagesCompleted: number; // Number of stages completed
    totalStages: number; // Total number of stages in the pipeline
    highestScore: number; // Highest score from any stage
    lowestScore: number; // Lowest score from any stage
  } {
    const scores: Record<string, number> = {};
    let totalScore = 0;
    let count = 0;
    let highestScore = 0;
    let lowestScore = 100;
    
    // Process each result
    for (const [key, value] of Object.entries(results)) {
      if (value && value.result) {
        scores[key] = value.result.score;
        totalScore += value.result.score;
        count++;
        
        if (value.result.score > highestScore) {
          highestScore = value.result.score;
        }
        
        if (value.result.score < lowestScore) {
          lowestScore = value.result.score;
        }
      }
    }
    
    return {
      averageScore: count > 0 ? Math.round(totalScore / count) : 0,
      scores,
      stagesCompleted: count,
      totalStages: this.PIPELINE_STAGES.length,
      highestScore,
      lowestScore: count > 0 ? lowestScore : 0
    };
  }
  
  /**
   * Generate comprehensive feedback from all agent results
   * @param pipelineResult - Results from all pipeline stages
   * @returns Formatted feedback with insights from all agents
   */
  private generateComprehensiveFeedback(pipelineResult: IPipelineResult): string {
    // Start with the score summary
    let feedback = "## AI Evaluation Summary\n\n";
    
    // Add scoring feedback if available (try new format first, then old format)
    const scoringResult = 
      pipelineResult.results.ScoringFeedbackAgent?.result || 
      pipelineResult.results.scoringFeedback?.result;
      
    if (scoringResult) {
      feedback += `### Overall Assessment\n${scoringResult.feedback}\n\n`;
      feedback += `**Score:** ${scoringResult.score}/100\n\n`;
    }
    
    // Add requirements compliance feedback (try new format first, then old format)
    const reqResult = 
      pipelineResult.results.RequirementsComplianceAgent?.result || 
      pipelineResult.results.requirementsCompliance?.result;
      
    if (reqResult) {
      // Cast to any to access potential custom properties added at runtime
      const reqResultAny = reqResult as any;
      
      feedback += "### Requirements Compliance\n";
      feedback += `${reqResult.feedback}\n\n`;
      
      // Check if requirementsMet exists in the result (might be added at runtime)
      const requirementsMet = reqResultAny.requirementsMet || [];
      const requirementsNotMet = reqResultAny.requirementsNotMet || [];
      
      // Alternative: use missingRequirements from the standard interface
      const missingRequirements = reqResult.metadata.missingRequirements || [];
      
      if (requirementsMet.length > 0) {
        feedback += "**Requirements Met:**\n";
        requirementsMet.forEach((req: string) => {
          feedback += `- ✅ ${req}\n`;
        });
        feedback += "\n";
      }
      
      if (requirementsNotMet.length > 0 || missingRequirements.length > 0) {
        feedback += "**Requirements Not Met:**\n";
        
        // Use either custom requirements not met or interface-defined missing requirements
        const notMetList = requirementsNotMet.length > 0 ? 
          requirementsNotMet : missingRequirements;
          
        notMetList.forEach((req: string) => {
          feedback += `- ❌ ${req}\n`;
        });
        feedback += "\n";
      }
    }
    
    // Add code quality feedback (try new format first, then old format)
    const codeResult = 
      pipelineResult.results.CodeQualityAgent?.result || 
      pipelineResult.results.codeQuality?.result;
      
    if (codeResult) {
      // Cast to any to access potential custom properties added at runtime
      const codeResultAny = codeResult as any;
      
      feedback += "### Code Quality Assessment\n";
      feedback += `${codeResult.feedback}\n\n`;
      
      // Add detailed metrics if available (added at runtime)
      if (codeResultAny.metrics) {
        feedback += "**Code Quality Metrics:**\n";
        Object.entries(codeResultAny.metrics).forEach(([key, value]) => {
          feedback += `- ${key}: ${value}\n`;
        });
        feedback += "\n";
      }
    }
    
    // Add recommendation for architect
    feedback += "### Recommendation for Architect\n";
    
    switch (pipelineResult.finalDecision) {
      case EvaluationDecision.PASS:
        feedback += "This solution has passed all automated checks. Please verify the implementation details and provide final approval if appropriate.\n\n";
        break;
      case EvaluationDecision.REVIEW:
        feedback += "This solution requires human review. Some aspects meet requirements but others need careful verification.\n\n";
        break;
      case EvaluationDecision.FAIL:
        feedback += "This solution has failed one or more critical checks. Please review the issues outlined above before making a final decision.\n\n";
        break;
    }
    
    return feedback;
  }
  
  /**
   * Prepare solution for architect review after AI evaluation
   * This processes AI agent results and formats them for easy architect review
   * @param solution - The evaluated solution
   * @param pipelineResult - The result from the AI evaluation pipeline
   * @returns The solution with enhanced feedback for architect review
   */
  public prepareSolutionForArchitectReview(
    solution: ISolution, 
    pipelineResult: IPipelineResult
  ): ISolution {
    try {
      logger.info(`Preparing solution for architect review`, {
        solutionId: solution._id?.toString(),
        pipelineCompleted: pipelineResult.pipelineCompleted,
        finalDecision: pipelineResult.finalDecision
      });
      
      // Ensure solution has a context object
      if (!solution.context) {
        solution.context = {
          evaluationId: pipelineResult.traceId,
          pipelineResults: {},
          processingMetadata: {
            startTime: new Date(),
            agentProcessingTimes: {},
            retryCount: 0
          }
        };
      }
      
      // Store all pipeline results in the solution context
      solution.context.pipelineResults = pipelineResult.results;
      solution.context.challengeContext = pipelineResult.challengeContext;
      
      // Extract comprehensive feedback from scoring agent for architect review
      // Try the new format (ScoringFeedbackAgent) first, then fall back to the old format (scoringFeedback)
      const scoringResult = 
        pipelineResult.results.ScoringFeedbackAgent?.result || 
        pipelineResult.results.scoringFeedback?.result;
      
      if (scoringResult) {
        // Set feedback from AI for architect to review
        solution.feedback = this.generateComprehensiveFeedback(pipelineResult);
        
        // Set provisional score from AI evaluation
        solution.score = scoringResult.score;
      }
      
      // Process all failed checks to build comprehensive feedback
      const failedChecks: string[] = [];
      
      // Extract failed checks from each agent (might be added at runtime)
      Object.entries(pipelineResult.results).forEach(([agentName, result]) => {
        if (result && result.result) {
          // Cast to any to access potential custom properties added at runtime
          const resultAny = result.result as any;
          
          if (resultAny.failedChecks && Array.isArray(resultAny.failedChecks)) {
            resultAny.failedChecks.forEach((check: string) => {
              failedChecks.push(`[${agentName}] ${check}`);
            });
          }
          
          // Agent-specific metadata handling with proper type guards
          if ((agentName === 'spamFiltering' || agentName === 'SpamFilteringAgent') && 'metadata' in result.result) {
            // Check for spam filtering metadata (spamIndicators)
            const spamMetadata = result.result.metadata as ISpamFilteringResult['metadata'];
            if (spamMetadata && Array.isArray(spamMetadata.spamIndicators)) {
              spamMetadata.spamIndicators.forEach((indicator: string) => {
                failedChecks.push(`[${agentName}] ${indicator}`);
              });
            }
          }
          
          if ((agentName === 'requirementsCompliance' || agentName === 'RequirementsComplianceAgent') && 'metadata' in result.result) {
            // Check for requirements compliance metadata (missingRequirements)
            const reqMetadata = result.result.metadata as IRequirementsComplianceResult['metadata'];
            if (reqMetadata && Array.isArray(reqMetadata.missingRequirements)) {
              reqMetadata.missingRequirements.forEach((requirement: string) => {
                failedChecks.push(`[${agentName}] Missing requirement: ${requirement}`);
              });
            }
          }
        }
      });
      
      // Add failed checks to solution context for architect review
      if (failedChecks.length > 0) {
        solution.context.failedChecks = failedChecks;
      }
      
      // Add metrics to context
      solution.context.metrics = this.getMetricsFromResults(pipelineResult.results);
      
      // Add processing metadata
      solution.context.processingMetadata = {
        ...solution.context.processingMetadata,
        totalProcessingTimeMs: pipelineResult.processingTimeMs,
        completedAt: new Date(),
        deeperAnalysisMode: solution.context.deeperAnalysisMode || false
      };
      
      logger.info(`Solution prepared for architect review`, {
        solutionId: solution._id?.toString(),
        score: solution.score,
        feedbackLength: solution.feedback?.length || 0,
        failedChecksCount: failedChecks.length
      });
      
      return solution;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error preparing solution for architect review`, {
        solutionId: solution._id?.toString(),
        error: errorMessage
      });
      
      // Ensure we still return the solution even if processing fails
      return solution;
    }
  }
  
  /**
   * Execute iterative pipeline with multiple evaluation passes if needed
   * @param solution - The solution to evaluate
   * @param maxPasses - Maximum number of evaluation passes
   * @returns Result of the pipeline execution
   */
  public async executeIterativePipeline(solution: ISolution, maxPasses: number = 2): Promise<IPipelineResult> {
    // Initialize result with default values to avoid null
    let result: IPipelineResult = {
      success: false,
      pipelineCompleted: false,
      results: {},
      finalDecision: EvaluationDecision.REVIEW,
      processingTimeMs: 0,
      traceId: uuidv4()
    };
    
    let currentPass = 0;
    let confidence = 0;
    
    // Initialize processing metadata
    if (!solution.context) {
      solution.context = {
        evaluationId: uuidv4(),
        pipelineResults: {},
        processingMetadata: {
          startTime: new Date(),
          agentProcessingTimes: {},
          retryCount: 0
        }
      };
    } else if (!solution.context.processingMetadata) {
      solution.context.processingMetadata = {
        startTime: new Date(),
        agentProcessingTimes: {},
        retryCount: 0
      };
    }
    
    while (currentPass < maxPasses) {
      // For pass > 0, enable deeper analysis mode
      if (currentPass > 0) {
        logger.info(`Starting deeper analysis pass ${currentPass + 1}/${maxPasses} for solution`, {
          solutionId: solution._id?.toString(),
          challengeId: solution.challenge?.toString()
        });
        
        // Set deeper analysis mode flag for subsequent passes
        if (solution.context) {
          solution.context.deeperAnalysisMode = true;
        }
      }
      
      // Execute pipeline
      const passStartTime = Date.now();
      result = await this.executePipeline(solution);
      
      // Update processing metadata
      if (solution.context?.processingMetadata) {
        solution.context.processingMetadata.retryCount = currentPass;
      }
      
      // Get confidence from scoring feedback
      confidence = result.results.scoringFeedback?.result.metadata.confidence || 0;
      
      // Log pass completion
      logger.info(`Completed evaluation pass ${currentPass + 1}/${maxPasses}`, {
        solutionId: solution._id?.toString(),
        pass: currentPass + 1,
        confidence,
        decision: result.finalDecision,
        processingTimeMs: Date.now() - passStartTime
      });
      
      // Break early if confidence is high enough or decision is final
      if (
        confidence >= 85 || 
        result.finalDecision === EvaluationDecision.FAIL ||
        !result.pipelineCompleted
      ) {
        break;
      }
      
      // Proceed to next pass
      currentPass++;
    }
    
    return result;
  }
}

// Export singleton instance
export const evaluationPipelineController = EvaluationPipelineController.getInstance();