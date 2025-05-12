import { AIAgentBase } from '../AIAgentBase';
import { 
  IScoringFeedbackResult, 
  ISolution, 
  ISpamFilteringResult,
  IRequirementsComplianceResult,
  ICodeQualityResult,
  EvaluationDecision,
  IExtendedScoringFeedbackMetadata
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { Types } from 'mongoose';
import { AIEvaluation } from '../../../models';
import { GitHubService } from '../../../services/github.service';
import { LLMService } from '../../llm/LLMService';
import { ILLMTextRequest } from '../../llm/interfaces/ILLMRequest';
import { ILLMService } from '../../llm/interfaces/ILLMService';

// Extended result interface that includes the decision
interface IExtendedScoringFeedbackResult extends IScoringFeedbackResult {
  metadata: IExtendedScoringFeedbackMetadata;
}

/**
 * Scoring and Feedback Agent
 * Integrates results from other agents and provides comprehensive LLM-powered scoring and feedback
 */
export class ScoringFeedbackAgent extends AIAgentBase<IScoringFeedbackResult> {
  private static instance: ScoringFeedbackAgent;
  
  public name = 'ScoringFeedbackAgent';
  public description = 'Generates final LLM-powered score and personalized feedback from all evaluations';
  
  // Scoring weights for different components (used as reference for the LLM)
  private readonly SCORING_WEIGHTS = {
    SPAM_FILTER: 0.10,       // 10% weight
    REQUIREMENTS: 0.40,      // 40% weight
    CODE_QUALITY: 0.50       // 50% weight
  };
  
  // Score thresholds for different evaluation outcomes
  private readonly SCORE_THRESHOLDS = {
    EXCELLENT: 85,           // Excellent submissions (85-100)
    GOOD: 70,                // Good submissions (70-84)
    ACCEPTABLE: 50,          // Acceptable submissions (50-69)
    NEEDS_IMPROVEMENT: 30    // Needs significant improvement (0-49)
  };
  
  // LLM service for advanced analysis
  private readonly llmService: ILLMService;

  /**
   * Private constructor to enforce singleton pattern
   * @param llmService - LLM service for scoring and feedback generation
   */
  private constructor() {
    super();
    this.llmService = LLMService.getInstance();
  }
  
  /**
   * Get singleton instance of the ScoringFeedbackAgent
   * @returns The ScoringFeedbackAgent instance
   */
  public static getInstance(): ScoringFeedbackAgent {
    if (!ScoringFeedbackAgent.instance) {
      ScoringFeedbackAgent.instance = new ScoringFeedbackAgent();
    }
    return ScoringFeedbackAgent.instance;
  }

  /**
   * Evaluate a solution for final scoring and feedback generation
   * @param solution - The solution to evaluate
   * @returns Evaluation result with integrated scoring and feedback
   */
  public async evaluateInternal(solution: ISolution): Promise<IScoringFeedbackResult> {
    try {
      // First, check if we have previous agent results in the solution context
      if (!solution.context || !solution.context.pipelineResults) {
        // Try to find the evaluation record in the database
        const evaluation = await AIEvaluation.findOne({ solution: solution._id });
        
        if (!evaluation) {
          logger.error(`No evaluation record or context found for solution`, {
            solutionId: solution._id?.toString()
          });
          
          return this.createDefaultResult(
            'Unable to generate comprehensive feedback due to missing evaluation data.'
          );
        }
        
        // Use the evaluation data from the database
        const spamFilteringResult = evaluation.spamFiltering;
        const requirementsComplianceResult = evaluation.requirementsCompliance;
        const codeQualityResult = evaluation.codeQuality;
        
        // Check if we have all the required previous evaluations
        if (!spamFilteringResult || !requirementsComplianceResult || !codeQualityResult) {
          const missingSteps = [];
          if (!spamFilteringResult) missingSteps.push('spam filtering');
          if (!requirementsComplianceResult) missingSteps.push('requirements compliance');
          if (!codeQualityResult) missingSteps.push('code quality');
          
          logger.warn(`Missing evaluation steps for comprehensive scoring`, {
            solutionId: solution._id?.toString(),
            missingSteps
          });
          
          return this.createDefaultResult(
            `Unable to generate comprehensive feedback due to missing evaluation steps: ${missingSteps.join(', ')}.`
          );
        }
        
        // Populate the solution context for LLM-based scoring
        if (!solution.context) {
          solution.context = { evaluationId: solution._id?.toString(), pipelineResults: {} };
        }
        
        solution.context.pipelineResults = {
          spamFiltering: spamFilteringResult,
          requirementsCompliance: requirementsComplianceResult,
          codeQuality: codeQualityResult
        };
      }
      
      // Extract the previous agent results from the solution context
      const pipelineResults = solution.context.pipelineResults;
      const spamFilteringResult = pipelineResults.spamFiltering as ISpamFilteringResult;
      const requirementsComplianceResult = pipelineResults.requirementsCompliance as IRequirementsComplianceResult;
      const codeQualityResult = pipelineResults.codeQuality as ICodeQualityResult;
      
      // Check if the submission was identified as spam
      if (spamFilteringResult.metadata.isSpam || spamFilteringResult.score < this.SCORE_THRESHOLDS.NEEDS_IMPROVEMENT) {
        const result: IExtendedScoringFeedbackResult = {
          score: Math.min(this.SCORE_THRESHOLDS.NEEDS_IMPROVEMENT, spamFilteringResult.score),
          feedback: 'This submission was flagged as potentially inappropriate. ' + 
                    'Please review the submission guidelines and ensure your submission meets the requirements.',
          metadata: {
            componentScores: {
              spamFilter: spamFilteringResult.score,
              requirements: 0,
              codeQuality: 0
            },
            weightedScore: Math.min(this.SCORE_THRESHOLDS.NEEDS_IMPROVEMENT, spamFilteringResult.score),
            confidence: 90,
            humanReviewRecommended: true,
            strengths: [],
            weaknesses: ['Submission flagged by spam/validity filter'],
            suggestedFeedback: 'Your submission has been flagged by our automated system. ' +
                              'Please ensure your GitHub repository contains relevant code for this challenge ' +
                              'and meets all the submission guidelines.',
            suggestedArchitects: [],
            priorityLevel: 'low',
            decision: EvaluationDecision.FAIL
          },
          evaluatedAt: new Date()
        };
        
        return result;
      }
      
      // If the submission passed spam filtering, use LLM to generate comprehensive scoring and feedback
      const llmScoringResult = await this.generateLLMScoring(
        solution,
        spamFilteringResult,
        requirementsComplianceResult,
        codeQualityResult
      );
      
      // Determine matching architects for review
      const matchingArchitects = await this.findMatchingArchitects(
        solution,
        llmScoringResult.score,
        codeQualityResult.metadata
      );
      
      // Prepare the final result
      const result: IExtendedScoringFeedbackResult = {
        score: llmScoringResult.score,
        feedback: llmScoringResult.feedback,
        metadata: {
          componentScores: {
            spamFilter: spamFilteringResult.score,
            requirements: requirementsComplianceResult.score,
            codeQuality: codeQualityResult.score
          },
          weightedScore: llmScoringResult.score,
          confidence: llmScoringResult.confidence,
          humanReviewRecommended: llmScoringResult.score >= this.SCORE_THRESHOLDS.GOOD,
          strengths: llmScoringResult.strengths,
          weaknesses: llmScoringResult.weaknesses,
          suggestedFeedback: llmScoringResult.suggestedFeedback,
          suggestedArchitects: matchingArchitects,
          priorityLevel: this.determinePriorityLevel(llmScoringResult.score),
          decision: this.determineFinalDecision(
            llmScoringResult.score,
            requirementsComplianceResult,
            codeQualityResult
          )
        },
        evaluatedAt: new Date()
      };
      
      logger.info(`Generated comprehensive LLM-powered scoring and feedback`, {
        solutionId: solution._id?.toString(),
        score: result.score,
        decision: result.metadata.decision,
        strengths: result.metadata.strengths.length,
        weaknesses: result.metadata.weaknesses.length
      });
      
      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;
      
      logger.error(`Error in scoring and feedback generation`, {
        solutionId: solution._id?.toString(),
        error: errorMessage,
        stack: errorStack
      });
      
      return this.createDefaultResult(
        `Error generating comprehensive feedback: ${errorMessage}`
      );
    }
  }
  
  /**
   * Generate comprehensive scoring and feedback using LLM
   * @param solution - The solution being evaluated
   * @param spamFilteringResult - Spam filtering result
   * @param requirementsComplianceResult - Requirements compliance result
   * @param codeQualityResult - Code quality result
   * @returns LLM-generated scoring and feedback
   */
  private async generateLLMScoring(
    solution: ISolution,
    spamFilteringResult: ISpamFilteringResult,
    requirementsComplianceResult: IRequirementsComplianceResult,
    codeQualityResult: ICodeQualityResult
  ): Promise<{
    score: number;
    feedback: string;
    confidence: number;
    strengths: string[];
    weaknesses: string[];
    suggestedFeedback: string;
  }> {
    try {
      // Extract GitHub repository information
      const repoInfo = await this.extractGitHubRepoInfo(solution.submissionUrl);
      
      // Prepare analysis summary for LLM
      // For spam filtering - handle potential missing properties
      const spamSummary = `Spam Filtering Score: ${spamFilteringResult.score}/100
Primary findings: ${(spamFilteringResult.metadata as any).primaryReason || 'No issues detected'}
Repository legitimacy: ${(spamFilteringResult.metadata as any).isLegitimate ? 'Legitimate' : 'Questionable'}`;
      
      // For requirements compliance - handle potential missing properties
      const requirementsSummary = `Requirements Compliance Score: ${requirementsComplianceResult.score}/100
Requirements satisfied: ${requirementsComplianceResult.metadata.requirementsSatisfied} out of ${requirementsComplianceResult.metadata.totalRequirements}
Missing requirements: ${requirementsComplianceResult.metadata.missingRequirements.join(', ') || 'None'}
Implementation quality: ${(requirementsComplianceResult.metadata as any).implementationQuality || 'Standard'}`;
      
      // For code quality
      const codeQualitySummary = `Code Quality Score: ${codeQualityResult.score}/100
Code Style: ${codeQualityResult.metadata.codeStyle}/100
Security: ${codeQualityResult.metadata.security}/100
Performance: ${codeQualityResult.metadata.performance}/100
Maintainability: ${codeQualityResult.metadata.maintainability}/100
Vulnerabilities: ${codeQualityResult.metadata.vulnerabilities.length} detected
Lines of code: ${codeQualityResult.metadata.codeMetrics.linesOfCode}
Test coverage: ${codeQualityResult.metadata.codeMetrics.testCoverage || 0}%`;
      
      // Include LLM-enhanced analysis if available
      let llmEnhancedAnalysis = '';
      if (codeQualityResult.metadata.llmAnalysis) {
        const llmAnalysis = codeQualityResult.metadata.llmAnalysis;
        
        // Include architecture analysis if available
        if (llmAnalysis.architectureAnalysis) {
          const archAnalysis = llmAnalysis.architectureAnalysis;
          
          llmEnhancedAnalysis += `
Architecture Analysis:
- Architecture Score: ${archAnalysis.architectureScore}/100
- Design Patterns: ${archAnalysis.designPatterns.join(', ') || 'None detected'}
- Architecture Strengths: ${archAnalysis.strengths.join(', ') || 'None highlighted'}
- Architecture Weaknesses: ${archAnalysis.weaknesses.join(', ') || 'None highlighted'}
- Recommendations: ${archAnalysis.architectureRecommendations.join(', ') || 'None provided'}`;
        }
        
        // Include file analysis insights
        if (llmAnalysis.fileAnalysis) {
          const fileAnalyses = Object.keys(llmAnalysis.fileAnalysis);
          if (fileAnalyses.length > 0) {
            llmEnhancedAnalysis += `
File Analysis:
- Files analyzed: ${fileAnalyses.length}`;
            
            // Collect best practices and security insights
            const allBestPractices = new Set<string>();
            const allSecurityInsights = new Set<string>();
            
            for (const filePath of fileAnalyses) {
              const fileAnalysis = llmAnalysis.fileAnalysis[filePath];
              
              fileAnalysis.bestPractices.forEach((practice: string) => allBestPractices.add(practice));
              fileAnalysis.securityInsights.forEach((insight: string) => allSecurityInsights.add(insight));
            }
            
            // Add practices and insights
            if (allBestPractices.size > 0) {
              llmEnhancedAnalysis += `
- Best Practices: ${Array.from(allBestPractices).join(', ')}`;
            }
            
            if (allSecurityInsights.size > 0) {
              llmEnhancedAnalysis += `
- Security Insights: ${Array.from(allSecurityInsights).join(', ')}`;
            }
          }
        }
      }
      
      // Create system prompt for scoring
      const systemPrompt = `You are an expert evaluator of coding submissions for an educational platform called XcelCrowd. 
Your task is to provide a final comprehensive score and feedback for a student submission.

The scoring is based on three main components with the following weights:
- Spam Filtering: 10% weight
- Requirements Compliance: 40% weight
- Code Quality: 50% weight

The score thresholds are:
- Excellent: 85-100
- Good: 70-84
- Acceptable: 50-69
- Needs Improvement: 0-49

Based on the results of previous evaluation stages, provide:
1. A final weighted score (0-100)
2. Your confidence in this score (0-100)
3. A brief overall feedback message (1-2 sentences)
4. List of strengths (3-5 bullet points)
5. List of weaknesses (3-5 bullet points)
6. Detailed suggested feedback for the student (3-5 sentences)

Format your response as a valid JSON object with the following structure:
{
  "score": number,
  "confidence": number,
  "feedback": "string",
  "strengths": ["string"],
  "weaknesses": ["string"],
  "suggestedFeedback": "string"
}`;

      // Prepare the LLM request
      const request: ILLMTextRequest = {
        model: "gpt-4o", // Using most capable model for comprehensive analysis
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Repository: ${repoInfo.owner}/${repoInfo.repo}

Previous evaluation results:

1. ${spamSummary}

2. ${requirementsSummary}

3. ${codeQualitySummary}

${llmEnhancedAnalysis}

Please analyze these results and provide a comprehensive final evaluation.` }
        ],
        temperature: 0.3,
        maxTokens: 2048,
        jsonMode: true,
        metadata: {
          source: "ScoringFeedbackAgent",
          repo: `${repoInfo.owner}/${repoInfo.repo}`,
          solutionId: solution._id?.toString() || 'unknown'
        }
      };

      // Call LLM service
      const response = await this.llmService.generateText(request);
      
      // Parse response
      try {
        const result = JSON.parse(response.text);
        
        return {
          score: Math.round(result.score) || 50,
          feedback: result.feedback || 'Analysis completed successfully.',
          confidence: Math.round(result.confidence) || 70,
          strengths: result.strengths || [],
          weaknesses: result.weaknesses || [],
          suggestedFeedback: result.suggestedFeedback || 'Thank you for your submission.'
        };
      } catch (parseError) {
        logger.warn(`Error parsing LLM response for scoring`, {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          text: response.text.substring(0, 200) + "..."
        });
        
        // Fall back to a weighted scoring method
        const weightedScore = Math.round(
          (spamFilteringResult.score * this.SCORING_WEIGHTS.SPAM_FILTER) +
          (requirementsComplianceResult.score * this.SCORING_WEIGHTS.REQUIREMENTS) +
          (codeQualityResult.score * this.SCORING_WEIGHTS.CODE_QUALITY)
        );
        
        return {
          score: weightedScore,
          feedback: 'Analysis completed with limited insights due to processing errors.',
          confidence: 60,
          strengths: ['Submission was processed successfully'],
          weaknesses: ['Unable to provide detailed insights due to processing limitation'],
          suggestedFeedback: 'Thank you for your submission. Our system has evaluated your code but encountered some limitations in providing detailed feedback.'
        };
      }
    } catch (error) {
      logger.error(`Error in LLM scoring generation`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Fall back to a weighted scoring method
      const weightedScore = Math.round(
        (spamFilteringResult.score * this.SCORING_WEIGHTS.SPAM_FILTER) +
        (requirementsComplianceResult.score * this.SCORING_WEIGHTS.REQUIREMENTS) +
        (codeQualityResult.score * this.SCORING_WEIGHTS.CODE_QUALITY)
      );
      
      return {
        score: weightedScore,
        feedback: 'Analysis completed with conventional scoring due to AI processing errors.',
        confidence: 70,
        strengths: [],
        weaknesses: [],
        suggestedFeedback: 'Thank you for your submission. It has been evaluated using our conventional scoring method.'
      };
    }
  }
  
  /**
   * Create a default result for error cases
   * @param errorMessage - Error message
   * @returns Default scoring result
   */
  private createDefaultResult(errorMessage: string): IExtendedScoringFeedbackResult {
    return {
      score: 50, // Default middle score
      feedback: errorMessage,
      metadata: {
        componentScores: {
          spamFilter: 0,
          requirements: 0,
          codeQuality: 0
        },
        weightedScore: 50,
        confidence: 0,
        humanReviewRecommended: true,
        strengths: [],
        weaknesses: ['Evaluation process encountered errors'],
        suggestedFeedback: 'We encountered an issue while evaluating your submission. ' +
                          'An administrator will review your submission manually.',
        suggestedArchitects: [],
        priorityLevel: 'low',
        decision: EvaluationDecision.REVIEW
      },
      evaluatedAt: new Date()
    };
  }
  
  /**
   * Determine the priority level for architect review
   * @param score - Final submission score
   * @returns Priority level
   */
  private determinePriorityLevel(score: number): 'low' | 'medium' | 'high' {
    if (score >= this.SCORE_THRESHOLDS.EXCELLENT) {
      return 'high';
    } else if (score >= this.SCORE_THRESHOLDS.GOOD) {
      return 'medium';
    } else {
      return 'low';
    }
  }
  
  /**
   * Determine the final decision based on scores and critical issues
   * @param score - Final weighted score
   * @param requirementsResult - Requirements compliance result
   * @param codeQualityResult - Code quality result
   * @returns Final evaluation decision
   */
  private determineFinalDecision(
    score: number,
    requirementsResult: IRequirementsComplianceResult,
    codeQualityResult: ICodeQualityResult
  ): EvaluationDecision {
    // Critical failures that would result in rejection regardless of score
    const hasCriticalVulnerabilities = codeQualityResult.metadata.vulnerabilities.some(
      v => v.severity === 'critical'
    );
    
    // Check for critical requirement failures
    // Use the ratio of satisfied requirements to total requirements
    const requirementRatio = requirementsResult.metadata.requirementsSatisfied / 
                            requirementsResult.metadata.totalRequirements;
    const hasCriticalRequirementFailure = requirementRatio < 0.7; // Less than 70% of requirements met
    
    if (hasCriticalVulnerabilities && hasCriticalRequirementFailure) {
      return EvaluationDecision.FAIL;
    } else if (score < this.SCORE_THRESHOLDS.ACCEPTABLE) {
      // Below the minimum acceptable threshold
      return EvaluationDecision.FAIL;
    } else if (score >= this.SCORE_THRESHOLDS.GOOD) {
      // High scores pass automatically
      return EvaluationDecision.PASS;
    } else {
      // Medium scores are sent for review
      return EvaluationDecision.REVIEW;
    }
  }
  
  /**
   * Find matching architects for review based on solution characteristics
   * @param solution - The solution being evaluated
   * @param score - Final submission score
   * @param codeQualityMetrics - Code quality metrics
   * @returns List of matching architects with scores
   */
  private async findMatchingArchitects(
    solution: ISolution,
    score: number,
    codeQualityMetrics: any
  ): Promise<Array<{
    architectId: Types.ObjectId;
    matchScore: number;
    expertise: string[];
  }>> {
    // In a production system, this would query a database of architects
    // For this implementation, we'll return placeholder data
    
    const placeholderArchitects = [
      {
        architectId: new Types.ObjectId(),
        matchScore: 95,
        expertise: ['JavaScript', 'TypeScript', 'React']
      },
      {
        architectId: new Types.ObjectId(),
        matchScore: 85,
        expertise: ['Node.js', 'Express', 'MongoDB']
      },
      {
        architectId: new Types.ObjectId(),
        matchScore: 75,
        expertise: ['Python', 'Django', 'SQL']
      }
    ];
    
    // Only select architects for high-scoring submissions
    return score >= this.SCORE_THRESHOLDS.GOOD ? placeholderArchitects : [];
  }
  
  /**
   * Override determineDecision to provide final evaluation decision
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or request review
   */
  public determineDecision(result: IScoringFeedbackResult): EvaluationDecision {
    // The ScoringFeedbackAgent never rejects submissions
    // It only provides a decision suggestion for the system
    
    // If the result has extended metadata with a decision, use that
    if ('metadata' in result && 'decision' in result.metadata) {
      return (result as IExtendedScoringFeedbackResult).metadata.decision;
    }
    
    // Otherwise, determine based on score
    if (result.score >= this.SCORE_THRESHOLDS.ACCEPTABLE) {
      return EvaluationDecision.PASS;
    } else {
      return EvaluationDecision.REVIEW;
    }
  }
  
  /**
   * Extract GitHub repository information from URL
   * @param submissionUrl - The URL submitted by the student
   * @returns Object containing repository information
   */
  private async extractGitHubRepoInfo(submissionUrl: string): Promise<{
    owner: string;
    repo: string;
    url: string
  }> {
    return GitHubService.extractGitHubRepoInfo(submissionUrl);
  }
}

// Export singleton instance
export const scoringFeedbackAgent = ScoringFeedbackAgent.getInstance(); 