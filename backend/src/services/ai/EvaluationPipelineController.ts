import { AIAgentFactory } from './AIAgentFactory';
import { 
  ISolution, 
  IStandardizedEvaluationResponse, 
  EvaluationDecision,
  ISpamFilteringResult,
  IRequirementsComplianceResult,
  ICodeQualityResult,
  IScoringFeedbackResult,
  ChallengeStatus,
  ChallengeDifficulty
} from '../../models/interfaces';
import { logger } from '../../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { Challenge } from '../../models';
import { LLMService } from '../llm/LLMService';
import { ILLMTextRequest } from '../llm/interfaces/ILLMRequest';
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
 */
export interface IPipelineResult {
  success: boolean;
  pipelineCompleted: boolean;
  stoppedAt?: string;
  reason?: string;
  results: {
    spamFiltering?: IStandardizedEvaluationResponse<ISpamFilteringResult>;
    requirementsCompliance?: IStandardizedEvaluationResponse<IRequirementsComplianceResult>;
    codeQuality?: IStandardizedEvaluationResponse<ICodeQualityResult>;
    scoringFeedback?: IStandardizedEvaluationResponse<IScoringFeedbackResult>;
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
  private readonly llmService: LLMService;
  
  // Define the evaluation pipeline stages and their execution order
  private readonly PIPELINE_STAGES = [
    'SpamFilteringAgent',
    'RequirementsComplianceAgent',
    'CodeQualityAgent',
    'ScoringFeedbackAgent'
  ];
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    this.agentFactory = AIAgentFactory.getInstance();
    this.llmService = LLMService.getInstance();
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
    
    try {
      logger.info(`Starting evaluation pipeline for solution`, {
        solutionId: solution._id?.toString(),
        challengeId: solution.challenge?.toString(),
        traceId
      });
      
      // Analyze challenge context first
      const challengeContext = solution.challenge 
        ? await this.analyzeChallengeContext(solution.challenge.toString())
        : null;
      
      // Initialize solution context if it doesn't exist
      if (!solution.context) {
        solution.context = {
          evaluationId: traceId,
          pipelineResults: {}
        };
      }
      
      // Add challenge context to solution context
      if (challengeContext) {
        solution.context.challengeContext = challengeContext;
      }
      
      // Execute each agent in sequence
      for (const stageName of this.PIPELINE_STAGES) {
        logger.debug(`Executing pipeline stage: ${stageName}`, {
          solutionId: solution._id?.toString(),
          stage: stageName,
          traceId
        });
        
        // Get the agent for this stage
        const agent = this.agentFactory.getAgent(stageName);
        
        // Execute the agent
        const stageResult = await agent.evaluate(solution);
        
        // Store the result based on agent type
        if (stageName === 'SpamFilteringAgent') {
          results.spamFiltering = stageResult as IStandardizedEvaluationResponse<ISpamFilteringResult>;
          // Store in solution context for next agents
          if (solution.context.pipelineResults) {
            solution.context.pipelineResults.spamFiltering = stageResult;
          }
        } else if (stageName === 'RequirementsComplianceAgent') {
          results.requirementsCompliance = stageResult as IStandardizedEvaluationResponse<IRequirementsComplianceResult>;
          // Store in solution context for next agents
          if (solution.context.pipelineResults) {
            solution.context.pipelineResults.requirementsCompliance = stageResult;
          }
        } else if (stageName === 'CodeQualityAgent') {
          results.codeQuality = stageResult as IStandardizedEvaluationResponse<ICodeQualityResult>;
          // Store in solution context for next agents
          if (solution.context.pipelineResults) {
            solution.context.pipelineResults.codeQuality = stageResult;
          }
        } else if (stageName === 'ScoringFeedbackAgent') {
          results.scoringFeedback = stageResult as IStandardizedEvaluationResponse<IScoringFeedbackResult>;
          // Store in solution context
          if (solution.context.pipelineResults) {
            solution.context.pipelineResults.scoringFeedback = stageResult;
          }
        }
        
        // Check if we should continue to the next stage
        if (stageResult.decision === EvaluationDecision.FAIL) {
          logger.info(`Pipeline stopped at ${stageName} with FAIL decision`, {
            solutionId: solution._id?.toString(),
            stage: stageName,
            score: stageResult.result.score,
            traceId
          });
          
          // Return early with results up to this point
          return {
            success: true,
            pipelineCompleted: false,
            stoppedAt: stageName,
            reason: stageResult.message,
            results,
            finalDecision: EvaluationDecision.FAIL,
            processingTimeMs: Date.now() - startTime,
            traceId,
            challengeContext: solution.context.challengeContext
          };
        }
        
        // REVIEW decisions allow pipeline to continue, but the final decision will be review
        if (stageResult.decision === EvaluationDecision.REVIEW) {
          logger.info(`Stage ${stageName} requested REVIEW but pipeline continues`, {
            solutionId: solution._id?.toString(),
            stage: stageName,
            score: stageResult.result.score,
            traceId
          });
        }
      }
      
      // All stages completed successfully
      // Determine the final decision based on the results of all stages
      const finalDecision = this.determineFinalDecision(results);
      
      logger.info(`Completed evaluation pipeline for solution`, {
        solutionId: solution._id?.toString(),
        finalDecision,
        processingTimeMs: Date.now() - startTime,
        traceId
      });
      
      return {
        success: true,
        pipelineCompleted: true,
        results,
        finalDecision,
        processingTimeMs: Date.now() - startTime,
        traceId,
        challengeContext: solution.context.challengeContext
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      
      logger.error(`Error in evaluation pipeline`, {
        solutionId: solution._id?.toString(),
        error: errorMessage,
        stack: errorStack,
        traceId
      });
      
      return {
        success: false,
        pipelineCompleted: false,
        stoppedAt: Object.keys(results).length > 0 
          ? this.PIPELINE_STAGES[Object.keys(results).length] 
          : this.PIPELINE_STAGES[0],
        reason: `Pipeline error: ${errorMessage}`,
        results,
        finalDecision: EvaluationDecision.FAIL,
        processingTimeMs: Date.now() - startTime,
        traceId
      };
    }
  }
  
  /**
   * Determine the final decision based on all stage results
   * @param results - The results from all pipeline stages
   * @returns The final decision for the solution
   */
  private determineFinalDecision(results: IPipelineResult['results']): EvaluationDecision {
    // If ScoringFeedbackAgent ran, use its decision
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
    averageScore: number;
    scores: Record<string, number>;
    stagesCompleted: number;
    totalStages: number;
    highestScore: number;
    lowestScore: number;
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
    
    // Add scoring feedback if available
    if (pipelineResult.results.scoringFeedback?.result) {
      const scoringResult = pipelineResult.results.scoringFeedback.result;
      feedback += `### Overall Assessment\n${scoringResult.feedback}\n\n`;
      feedback += `**Score:** ${scoringResult.score}/100\n\n`;
    }
    
    // Add requirements compliance feedback
    if (pipelineResult.results.requirementsCompliance?.result) {
      const reqResult = pipelineResult.results.requirementsCompliance.result;
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
    
    // Add code quality feedback
    if (pipelineResult.results.codeQuality?.result) {
      const codeResult = pipelineResult.results.codeQuality.result;
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
      if (pipelineResult.results.scoringFeedback) {
        const scoringResult = pipelineResult.results.scoringFeedback.result;
        
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
          if (agentName === 'spamFiltering' && 'metadata' in result.result) {
            // Check for spam filtering metadata (spamIndicators)
            const spamMetadata = result.result.metadata as ISpamFilteringResult['metadata'];
            if (spamMetadata && Array.isArray(spamMetadata.spamIndicators)) {
              spamMetadata.spamIndicators.forEach((indicator: string) => {
                failedChecks.push(`[${agentName}] ${indicator}`);
              });
            }
          }
          
          if (agentName === 'requirementsCompliance' && 'metadata' in result.result) {
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