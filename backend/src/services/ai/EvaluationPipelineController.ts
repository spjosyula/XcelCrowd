import { AIAgentFactory } from './AIAgentFactory';
import { 
  ISolution, 
  IStandardizedEvaluationResponse, 
  IAgentEvaluationResult,
  EvaluationDecision,
  ISpamFilteringResult,
  IRequirementsComplianceResult,
  ICodeQualityResult,
  IScoringFeedbackResult
} from '../../models/interfaces';
import { logger } from '../../utils/logger';
import { v4 as uuidv4 } from 'uuid';

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
        traceId
      });
      
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
        } else if (stageName === 'RequirementsComplianceAgent') {
          results.requirementsCompliance = stageResult as IStandardizedEvaluationResponse<IRequirementsComplianceResult>;
        } else if (stageName === 'CodeQualityAgent') {
          results.codeQuality = stageResult as IStandardizedEvaluationResponse<ICodeQualityResult>;
        } else if (stageName === 'ScoringFeedbackAgent') {
          results.scoringFeedback = stageResult as IStandardizedEvaluationResponse<IScoringFeedbackResult>;
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
            traceId
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
        traceId
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
}

// Export singleton instance
export const evaluationPipelineController = EvaluationPipelineController.getInstance(); 