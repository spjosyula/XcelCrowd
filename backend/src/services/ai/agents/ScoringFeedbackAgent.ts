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

// Extended result interface that includes the decision
interface IExtendedScoringFeedbackResult extends IScoringFeedbackResult {
  metadata: IExtendedScoringFeedbackMetadata;
}

/**
 * Scoring and Feedback Agent
 * Integrates results from other agents and provides comprehensive scoring and feedback
 */
export class ScoringFeedbackAgent extends AIAgentBase<IScoringFeedbackResult> {
  public name = 'ScoringFeedbackAgent';
  public description = 'Generates final score and personalized feedback from all evaluations';
  
  // Scoring weights for different components
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
  
  // Thresholds for component scores
  private readonly COMPONENT_THRESHOLDS = {
    STRONG: 80,              // Strong in this area
    ACCEPTABLE: 60,          // Acceptable in this area
    WEAK: 40                 // Weak in this area
  };

  
  
  /**
   * Evaluate a solution for final scoring and feedback generation
   * @param solution - The solution to evaluate
   * @returns Evaluation result with integrated scoring and feedback
   */
  public async evaluateInternal(solution: ISolution): Promise<IScoringFeedbackResult> {
    try {
      // Get the current evaluation record for this solution
      const evaluation = await AIEvaluation.findOne({ solution: solution._id });
      
      if (!evaluation) {
        logger.error(`No evaluation record found for solution`, {
          solutionId: solution._id?.toString()
        });
        
        return this.createDefaultResult(
          'Unable to generate comprehensive feedback due to missing evaluation data.'
        );
      }
      
      // Get the results from previous agents
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
      
      // If the submission passed spam filtering, proceed with comprehensive scoring
      
      // Extract component scores
      const spamFilterScore = spamFilteringResult.score;
      const requirementsScore = requirementsComplianceResult.score;
      const codeQualityScore = codeQualityResult.score;
      
      // Calculate weighted total score
      const weightedScore = Math.round(
        (spamFilterScore * this.SCORING_WEIGHTS.SPAM_FILTER) +
        (requirementsScore * this.SCORING_WEIGHTS.REQUIREMENTS) +
        (codeQualityScore * this.SCORING_WEIGHTS.CODE_QUALITY)
      );
      
      // Determine if human review is recommended
      // Human review is recommended for high-scoring submissions
      const humanReviewRecommended = weightedScore >= this.SCORE_THRESHOLDS.GOOD;
      
      // Determine priority level for architect review
      let priorityLevel: 'low' | 'medium' | 'high';
      
      if (weightedScore >= this.SCORE_THRESHOLDS.EXCELLENT) {
        priorityLevel = 'high';
      } else if (weightedScore >= this.SCORE_THRESHOLDS.GOOD) {
        priorityLevel = 'medium';
      } else {
        priorityLevel = 'low';
      }
      
      // Determine the final decision based on all evaluation criteria
      let decision: EvaluationDecision;
      
      // Critical failures that would result in rejection regardless of score
      const hasCriticalVulnerabilities = codeQualityResult.metadata.vulnerabilities.some(
        v => v.severity === 'critical'
      );
      
      // Check for critical requirement failures
      // Use the ratio of satisfied requirements to total requirements
      const requirementRatio = requirementsComplianceResult.metadata.requirementsSatisfied / 
                              requirementsComplianceResult.metadata.totalRequirements;
      const hasCriticalRequirementFailure = requirementRatio < 0.7; // Less than 70% of requirements met
      
      if (hasCriticalVulnerabilities || hasCriticalRequirementFailure) {
        decision = EvaluationDecision.FAIL;
      } else if (weightedScore < this.SCORE_THRESHOLDS.ACCEPTABLE) {
        // Below the minimum acceptable threshold
        decision = EvaluationDecision.FAIL;
      } else if (weightedScore >= this.SCORE_THRESHOLDS.GOOD) {
        // High scores pass automatically
        decision = EvaluationDecision.PASS;
      } else {
        // Medium scores are sent for review
        decision = EvaluationDecision.REVIEW;
      }
      
      // Collect strengths and weaknesses
      const strengths: string[] = [];
      const weaknesses: string[] = [];
      
      // Add strengths based on scores
      if (requirementsScore >= this.COMPONENT_THRESHOLDS.STRONG) {
        strengths.push('Strong adherence to project requirements');
      }
      
      if (codeQualityResult.metadata.codeStyle >= this.COMPONENT_THRESHOLDS.STRONG) {
        strengths.push('Excellent code style and formatting');
      }
      
      if (codeQualityResult.metadata.security >= this.COMPONENT_THRESHOLDS.STRONG) {
        strengths.push('Good security practices');
      }
      
      if (codeQualityResult.metadata.performance >= this.COMPONENT_THRESHOLDS.STRONG) {
        strengths.push('Efficient code performance');
      }
      
      if (codeQualityResult.metadata.maintainability >= this.COMPONENT_THRESHOLDS.STRONG) {
        strengths.push('Highly maintainable code structure');
      }
      
      // Add weaknesses based on scores
      if (requirementsScore < this.COMPONENT_THRESHOLDS.ACCEPTABLE) {
        weaknesses.push('Insufficient adherence to project requirements');
      }
      
      if (codeQualityResult.metadata.codeStyle < this.COMPONENT_THRESHOLDS.ACCEPTABLE) {
        weaknesses.push('Code style needs improvement');
      }
      
      if (codeQualityResult.metadata.security < this.COMPONENT_THRESHOLDS.ACCEPTABLE) {
        weaknesses.push('Security concerns need addressing');
      }
      
      if (codeQualityResult.metadata.performance < this.COMPONENT_THRESHOLDS.ACCEPTABLE) {
        weaknesses.push('Performance issues detected');
      }
      
      if (codeQualityResult.metadata.maintainability < this.COMPONENT_THRESHOLDS.ACCEPTABLE) {
        weaknesses.push('Code maintainability needs improvement');
      }
      
      // Add specific issues from requirements compliance
      if (requirementsComplianceResult.metadata.missingRequirements.length > 0) {
        const topMissingRequirements = requirementsComplianceResult.metadata.missingRequirements
          .slice(0, 3); // Limit to top 3 for readability
          
        weaknesses.push(
          'Missing requirements: ' + 
          topMissingRequirements.join(', ') + 
          (requirementsComplianceResult.metadata.missingRequirements.length > 3 ? 
           ` and ${requirementsComplianceResult.metadata.missingRequirements.length - 3} more` : '')
        );
      }
      
      // Add vulnerability issues
      if (codeQualityResult.metadata.vulnerabilities.length > 0) {
        const criticalVulns = codeQualityResult.metadata.vulnerabilities.filter(
          v => v.severity === 'critical' || v.severity === 'high'
        );
        
        if (criticalVulns.length > 0) {
          weaknesses.push(
            `${criticalVulns.length} critical security vulnerabilities detected that need immediate attention`
          );
        } else if (codeQualityResult.metadata.vulnerabilities.length > 0) {
          weaknesses.push(`${codeQualityResult.metadata.vulnerabilities.length} minor security vulnerabilities detected`);
        }
      }
      
      // Identify improvement areas from code quality metrics
      if (codeQualityResult.metadata.improvementAreas && 
          codeQualityResult.metadata.improvementAreas.length > 0) {
        
        codeQualityResult.metadata.improvementAreas.forEach(area => {
          if (!weaknesses.some(w => w.includes(area))) {
            weaknesses.push(`Improvement needed in: ${area}`);
          }
        });
      }
      
      // If there are too many weaknesses, consolidate them
      if (weaknesses.length > 5) {
        const criticalWeaknesses = weaknesses.filter(w => 
          w.includes('critical') || 
          w.includes('Missing requirements') || 
          w.includes('security')
        );
        
        const otherWeaknesses = weaknesses.filter(w => 
          !criticalWeaknesses.includes(w)
        );
        
        weaknesses.length = 0;
        weaknesses.push(...criticalWeaknesses);
        
        if (otherWeaknesses.length > 0) {
          weaknesses.push(`${otherWeaknesses.length} other areas need improvement`);
        }
      }
      
      // Generate suggested feedback based on scores and findings
      let suggestedFeedback = this.generateSuggestedFeedback(
        weightedScore,
        strengths,
        weaknesses,
        decision
      );
      
      // Find architects that would be good matches for this submission
      const suggestedArchitects = await this.findMatchingArchitects(
        solution,
        weightedScore,
        codeQualityResult.metadata
      );
      
      // Generate feedback message based on the evaluation
      let feedback = `Overall evaluation score: ${weightedScore}/100. `;
      
      if (weightedScore >= this.SCORE_THRESHOLDS.EXCELLENT) {
        feedback += 'This is an excellent submission that meets or exceeds expectations.';
      } else if (weightedScore >= this.SCORE_THRESHOLDS.GOOD) {
        feedback += 'This is a good submission with some areas for improvement.';
      } else if (weightedScore >= this.SCORE_THRESHOLDS.ACCEPTABLE) {
        feedback += 'This submission meets basic requirements but needs significant improvements.';
      } else {
        feedback += 'This submission needs major improvements to meet the requirements.';
      }
      
      // Add decision information
      if (decision === EvaluationDecision.FAIL) {
        feedback += ' Unfortunately, this submission does not meet the minimum criteria for acceptance.';
      } else if (decision === EvaluationDecision.REVIEW) {
        feedback += ' This submission requires review by an architect before final decision.';
      } else {
        feedback += ' This submission has been accepted and will be reviewed by an architect.';
      }
      
      const result: IExtendedScoringFeedbackResult = {
        score: weightedScore,
        feedback,
        metadata: {
          componentScores: {
            spamFilter: spamFilterScore,
            requirements: requirementsScore,
            codeQuality: codeQualityScore
          },
          weightedScore,
          confidence: 85, // Confidence in the evaluation
          humanReviewRecommended,
          strengths,
          weaknesses,
          suggestedFeedback,
          suggestedArchitects,
          priorityLevel,
          decision
        },
        evaluatedAt: new Date()
      };
      
      return result;
    } catch (error) {
      logger.error(`Error in scoring and feedback evaluation`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
      
      return this.createDefaultResult(
        'Unable to generate comprehensive feedback due to a technical error.'
      );
    }
  }
  
  /**
   * Create a default result when evaluation cannot be completed
   * @param errorMessage - The error message to include in feedback
   * @returns Default scoring and feedback result
   */
  private createDefaultResult(errorMessage: string): IExtendedScoringFeedbackResult {
    return {
      score: 50,
      feedback: errorMessage,
      metadata: {
        componentScores: {
          spamFilter: 50,
          requirements: 50,
          codeQuality: 50
        },
        weightedScore: 50,
        confidence: 30,
        humanReviewRecommended: true,
        strengths: [],
        weaknesses: ['Unable to complete evaluation'],
        suggestedFeedback: 'This submission requires manual review by an architect.',
        suggestedArchitects: [],
        priorityLevel: 'medium',
        decision: EvaluationDecision.REVIEW
      },
      evaluatedAt: new Date()
    };
  }
  
  /**
   * Generate personalized feedback based on evaluation results
   * @param score - The overall weighted score
   * @param strengths - Identified strengths
   * @param weaknesses - Identified weaknesses
   * @param decision - The evaluation decision
   * @returns Suggested feedback text
   */
  private generateSuggestedFeedback(
    score: number,
    strengths: string[],
    weaknesses: string[],
    decision: EvaluationDecision
  ): string {
    let feedback = '';
    
    // Opening statement based on score and decision
    if (decision === EvaluationDecision.FAIL) {
      feedback += 'Thank you for your submission. ';
    } else if (score >= this.SCORE_THRESHOLDS.EXCELLENT) {
      feedback += 'Excellent work on this submission! ';
    } else if (score >= this.SCORE_THRESHOLDS.GOOD) {
      feedback += 'Good job on this submission. ';
    } else {
      feedback += 'Thank you for your submission. ';
    }
    
    // Add strengths
    if (strengths.length > 0) {
      feedback += 'Here\'s what you did well: ';
      strengths.forEach((strength, index) => {
        if (index === 0) {
          feedback += strength;
        } else if (index === strengths.length - 1) {
          feedback += `, and ${strength}`;
        } else {
          feedback += `, ${strength}`;
        }
      });
      feedback += '. ';
    }
    
    // Add weaknesses and improvement suggestions
    if (weaknesses.length > 0) {
      feedback += 'Here are some areas for improvement: ';
      weaknesses.forEach((weakness, index) => {
        if (index === 0) {
          feedback += weakness;
        } else if (index === weaknesses.length - 1) {
          feedback += `, and ${weakness}`;
        } else {
          feedback += `, ${weakness}`;
        }
      });
      feedback += '. ';
    }
    
    // Add decision-specific information
    if (decision === EvaluationDecision.FAIL) {
      feedback += 'Unfortunately, your submission does not meet the minimum requirements for acceptance. Please review the feedback and consider making the suggested improvements before resubmitting.';
    } else if (decision === EvaluationDecision.REVIEW) {
      feedback += 'Your submission will be reviewed by one of our architects who will provide additional feedback.';
    } else {
      // Add encouraging closing for passing submissions
      if (score >= this.SCORE_THRESHOLDS.GOOD) {
        feedback += 'Keep up the good work! Your submission has been accepted and will be reviewed by an architect.';
      } else {
        feedback += 'Your submission has been accepted. With some improvements, your next submission could be even better!';
      }
    }
    
    return feedback;
  }
  
  /**
   * Find architects that would be good matches for reviewing this submission
   * @param solution - The solution being evaluated
   * @param score - The overall score
   * @param codeQualityMetrics - Code quality metrics
   * @returns Array of suggested architects
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
    try {
      // In a real implementation, this would:
      // 1. Query the database for architects with relevant expertise
      // 2. Match architect skills with the technologies used in the solution
      // 3. Consider architect availability and workload
      // 4. Calculate a match score for each architect
      
      // For demonstration purposes, we're returning simulated architect matches
      return [
        {
          architectId: new Types.ObjectId(),
          matchScore: 85,
          expertise: ['JavaScript', 'React', 'Node.js']
        },
        {
          architectId: new Types.ObjectId(),
          matchScore: 75,
          expertise: ['Full Stack', 'TypeScript', 'MongoDB']
        }
      ];
    } catch (error) {
      logger.error(`Error finding matching architects`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
      
      return [];
    }
  }
  
  /**
   * Override the default decision logic for the ScoringFeedbackAgent
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or review
   */
  protected determineDecision(result: IScoringFeedbackResult): EvaluationDecision {
    // According to requirements, any solution that reaches the Scoring agent
    // should automatically be accepted and sent to architects
    
    // We should never return FAIL at this stage
    const currentDecision = (result as IExtendedScoringFeedbackResult).metadata.decision;
    
    // If the decision is FAIL, change it to REVIEW
    if (currentDecision === EvaluationDecision.FAIL) {
      return EvaluationDecision.REVIEW;
    }
    
    // Otherwise, keep the existing decision (PASS or REVIEW)
    return currentDecision;
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