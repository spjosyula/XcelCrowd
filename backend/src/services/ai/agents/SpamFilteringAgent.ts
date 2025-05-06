import { AIAgentBase } from '../AIAgentBase';
import {
  ISpamFilteringResult,
  ISolution,
  EvaluationDecision
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { ApiError } from '../../../utils/api.error';
import { HTTP_STATUS } from '../../../models/interfaces';
import * as crypto from 'crypto';

// Define common patterns for spam repositories
import SPAM_PATTERNS from '../../../constants/spam.patterns';
import { GitHubService, IGitHubRepoDetails } from '../../../services/github.service';


/**
 * Spam/Bad Submission Filtering Agent
 * Acts as first-pass filter to identify spam or invalid GitHub submissions
 */
export class SpamFilteringAgent extends AIAgentBase<ISpamFilteringResult> {
  public name = 'SpamFilteringAgent';
  public description = 'Filters out spam or invalid GitHub submissions';

  // Cache of fingerprints for duplicate detection
  private static submissionFingerprints: Map<string, number> = new Map();

  /**
   * Evaluate a solution for spam or invalid submission
   * @param solution - The solution to evaluate
   * @returns Evaluation result with spam detection metrics
   */
  public async evaluateInternal(solution: ISolution): Promise<ISpamFilteringResult> {
    try {
      logger.debug(`Starting spam filtering evaluation`, {
        solutionId: solution._id?.toString(),
        submissionUrl: solution.submissionUrl
      });

      // Extract GitHub repository URL from submission
      const repoUrl = this.extractGitHubUrl(solution.submissionUrl);

      // Set up validation errors array to collect all issues
      const validationErrors: string[] = [];
      const spamIndicators: string[] = [];

      if (!repoUrl) {
        logger.warn(`Invalid GitHub URL in submission`, {
          solutionId: solution._id?.toString(),
          submissionUrl: solution.submissionUrl
        });

        return {
          score: 0,
          feedback: 'Submission URL is not a valid GitHub repository URL.',
          metadata: {
            isSpam: false,
            isValid: false,
            repositoryExists: false,
            repositoryAccessible: false,
            confidence: 100,
            spamIndicators: [],
            validationErrors: ['Invalid GitHub repository URL format']
          },
          evaluatedAt: new Date()
        };
      }

      // Use GitHubService to extract owner and repo from URL
      let owner, repo;
      try {
        const repoInfo = GitHubService.extractGitHubRepoInfo(repoUrl);
        owner = repoInfo.owner;
        repo = repoInfo.repo;
      } catch (error) {
        return {
          score: 0,
          feedback: 'Could not extract repository owner and name from URL.',
          metadata: {
            isSpam: false,
            isValid: false,
            repositoryExists: false,
            repositoryAccessible: false,
            confidence: 100,
            spamIndicators: [],
            validationErrors: ['Invalid GitHub repository URL structure']
          },
          evaluatedAt: new Date()
        };
      }

      // Check for repository fingerprint to detect duplicates
      const fingerprintKey = `${owner}/${repo}`;
      const duplicateCount = this.checkDuplicateSubmission(fingerprintKey);

      if (duplicateCount > SPAM_PATTERNS.MAX_IDENTICAL_SUBMISSIONS) {
        spamIndicators.push(`Repository has been submitted ${duplicateCount} times, exceeding the limit of ${SPAM_PATTERNS.MAX_IDENTICAL_SUBMISSIONS}`);
      }

      // Verify repository exists and is accessible using GitHubService
      const repoStatus = await GitHubService.verifyGitHubRepository(owner, repo);

      if (!repoStatus.exists) {
        return {
          score: 0,
          feedback: 'GitHub repository does not exist.',
          metadata: {
            isSpam: false,
            isValid: false,
            repositoryExists: false,
            repositoryAccessible: false,
            confidence: 100,
            spamIndicators: [],
            validationErrors: ['Repository does not exist']
          },
          evaluatedAt: new Date()
        };
      }

      if (!repoStatus.accessible) {
        return {
          score: 0,
          feedback: 'GitHub repository exists but is not accessible. It may be private or deleted.',
          metadata: {
            isSpam: false,
            isValid: false,
            repositoryExists: true,
            repositoryAccessible: false,
            confidence: 100,
            spamIndicators: [],
            validationErrors: ['Repository is not accessible']
          },
          evaluatedAt: new Date()
        };
      }

      // Now that we know the repo exists and is accessible, get the details
      const repoDetails = repoStatus.repoDetails;
      if (!repoDetails) {
        validationErrors.push('Could not retrieve repository details');
      } else {
        // Check for suspicious repository properties
        if (repoDetails.fork) {
          spamIndicators.push('Repository is a fork and may not be original work');
        }

        if (repoDetails.archived) {
          spamIndicators.push('Repository is archived and not actively maintained');
        }

        if (repoDetails.disabled) {
          spamIndicators.push('Repository is disabled');
          validationErrors.push('Repository is disabled');
        }

        // Check repository activity
        const createdAt = new Date(repoDetails.created_at);
        const updatedAt = new Date(repoDetails.updated_at);
        const pushedAt = new Date(repoDetails.pushed_at);
        const now = new Date();

        // If repo was created very recently (within 24 hours) and has no activity, that's suspicious
        if (now.getTime() - createdAt.getTime() < 24 * 60 * 60 * 1000 &&
          now.getTime() - pushedAt.getTime() > 12 * 60 * 60 * 1000) {
          spamIndicators.push('Repository was created recently but has no recent activity');
        }

        // If repository has never been updated since creation, that's suspicious
        if (createdAt.getTime() === updatedAt.getTime() &&
          createdAt.getTime() === pushedAt.getTime()) {
          spamIndicators.push('Repository has no activity since creation');
        }

        // Check for empty or very small repos
        if (repoDetails.size < 10) { // Size is in KB
          spamIndicators.push('Repository is very small (less than 10KB)');
        }
      }

      // Analyze repository contents
      const contentAnalysis = await this.analyzeRepositoryContents(owner, repo);

      if (contentAnalysis.isEmpty) {
        spamIndicators.push('Repository appears to be empty');
        validationErrors.push('Repository contains no files');
      }

      if (contentAnalysis.isMissingReadme) {
        spamIndicators.push('Repository is missing a README file');
      }

      if (contentAnalysis.hasLowFileCount) {
        spamIndicators.push(`Repository has very few files (${contentAnalysis.fileCount})`);
      }

      if (contentAnalysis.isTemplateOnly) {
        spamIndicators.push('Repository appears to contain only template files');
      }

      // Check for spam indicators in title, description and code
      const contentSpamIndicators = await this.detectSpamIndicators(solution, repoUrl, repoDetails);
      spamIndicators.push(...contentSpamIndicators);

      // Generate a composite spam score - we use a more nuanced approach here
      let score = 100; // Start with a perfect score

      // Deduct points for each validation error and spam indicator
      const validationErrorPenalty = 50 / (validationErrors.length > 0 ? validationErrors.length : 1);
      const spamIndicatorPenalty = 50 / (spamIndicators.length > 0 ? spamIndicators.length : 1);

      score -= validationErrors.length * validationErrorPenalty;
      score -= spamIndicators.length * spamIndicatorPenalty;

      // Ensure score is within bounds
      score = Math.max(0, Math.min(100, Math.round(score)));

      // Determine if this is spam - if score is below 30 or we have critical validation errors
      const isSpam = score < 30 || validationErrors.length > 0;

      // Generate feedback
      let feedback = '';
      if (isSpam) {
        feedback = 'Submission detected as potentially problematic. ';

        if (validationErrors.length > 0) {
          feedback += `Validation errors: ${validationErrors.join(', ')}. `;
        }

        if (spamIndicators.length > 0) {
          feedback += `Issues detected: ${spamIndicators.join(', ')}`;
        }
      } else {
        feedback = 'Submission passed spam and validity checks. ';

        if (spamIndicators.length > 0) {
          feedback += `Note: Some minor issues were detected: ${spamIndicators.join(', ')}`;
        }
      }

      return {
        score,
        feedback,
        metadata: {
          isSpam,
          isValid: !isSpam,
          repositoryExists: repoStatus.exists,
          repositoryAccessible: repoStatus.accessible,
          confidence: 95 - (spamIndicators.length * 5), // Reduce confidence with each indicator
          spamIndicators,
          validationErrors
        },
        evaluatedAt: new Date()
      };
    } catch (error) {
      logger.error(`Error in spam filtering evaluation`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });

      // Return a default result on error
      return {
        score: 50, // Neutral score on error
        feedback: 'Unable to completely verify submission validity due to technical issues.',
        metadata: {
          isSpam: false,
          isValid: true, // Give benefit of the doubt
          repositoryExists: true,
          repositoryAccessible: true,
          confidence: 30, // Low confidence due to error
          spamIndicators: [],
          validationErrors: [error instanceof Error ? error.message : 'Unknown error']
        },
        evaluatedAt: new Date()
      };
    }
  }

  /**
   * Extract GitHub repository URL from submission URL with robust security validation
   * @param submissionUrl - The URL submitted by the student
   * @returns Normalized GitHub repository URL or null if invalid
   */
  private extractGitHubUrl(submissionUrl: string): string | null {
    try {
      // Try to extract GitHub repository info using GitHubService
      const repoInfo = GitHubService.extractGitHubRepoInfo(submissionUrl);
      return repoInfo.url;
    } catch (error) {
      // If extraction fails, log and return null
      logger.error(`Error extracting GitHub URL`, {
        submissionUrl,
        error: error instanceof Error ? error.message : String(error)
      });
      return null;
    }
  }

  /**
   * Analyze repository contents to detect spam/template repositories
   * @param owner - The repository owner/username
   * @param repo - The repository name
   * @returns Analysis of repository contents
   */
  private async analyzeRepositoryContents(
    owner: string,
    repo: string
  ): Promise<{
    isEmpty: boolean;
    isMissingReadme: boolean;
    hasLowFileCount: boolean;
    isTemplateOnly: boolean;
    fileCount: number;
    hasCodeFiles: boolean;
  }> {
    try {
      // Use GitHubService to get repository contents
      const contents = await GitHubService.getRepositoryContents(owner, repo);

      // Check if repository is empty
      const isEmpty = contents.length === 0;

      // Check for README file
      const hasReadme = contents.some(file =>
        file.name.toLowerCase().includes('readme')
      );

      // Count files and check for code files
      const fileCount = contents.length;
      const hasLowFileCount = fileCount < SPAM_PATTERNS.MIN_FILES_COUNT;

      // Check if repository contains real code files or just template files
      const codeExtensions = ['.js', '.ts', '.py', '.java', '.c', '.cpp', '.h', '.cs', '.go', '.rb', '.php', '.html', '.css'];
      const hasCodeFiles = contents.some(file =>
        codeExtensions.some(ext => file.name.toLowerCase().endsWith(ext))
      );

      // Check if it's just a template repository
      // Template repos often have specific files like LICENSE, .github/*, etc.
      const templateOnlyFiles = [
        'license', '.github', 'contributing.md', 'code_of_conduct.md',
        '.gitignore', '.gitattributes', 'package.json', 'package-lock.json'
      ];

      const nonTemplateFiles = contents.filter(file =>
        !templateOnlyFiles.some(template => file.name.toLowerCase().includes(template))
      );

      const isTemplateOnly = nonTemplateFiles.length <= 1 && !hasCodeFiles;

      return {
        isEmpty,
        isMissingReadme: !hasReadme,
        hasLowFileCount,
        isTemplateOnly,
        fileCount,
        hasCodeFiles
      };
    } catch (error) {
      logger.error(`Error analyzing repository contents`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });

      // Return default values on error
      return {
        isEmpty: false,
        isMissingReadme: false,
        hasLowFileCount: false,
        isTemplateOnly: false,
        fileCount: 0,
        hasCodeFiles: false
      };
    }
  }

  /**
   * Check if a repository has been submitted multiple times
   * @param repoFingerprint - The fingerprint key for the repository
   * @returns The number of times this repo has been submitted
   */
  private checkDuplicateSubmission(repoFingerprint: string): number {
    // Create a hash of the repo fingerprint
    const hashedFingerprint = crypto
      .createHash('sha256')
      .update(repoFingerprint)
      .digest('hex');

    // Check if we've seen this repo before
    const currentCount = SpamFilteringAgent.submissionFingerprints.get(hashedFingerprint) || 0;

    // Increment the count
    SpamFilteringAgent.submissionFingerprints.set(hashedFingerprint, currentCount + 1);

    return currentCount + 1;
  }

  /**
   * Detect spam indicators in the submission
   * @param solution - The solution object
   * @param repoUrl - The GitHub repository URL
   * @param repoDetails - Repository details if available
   * @returns Array of spam indicators if found
   */
  private async detectSpamIndicators(
    solution: ISolution,
    repoUrl: string,
    repoDetails?: IGitHubRepoDetails
  ): Promise<string[]> {
    const indicators: string[] = [];

    // Check for empty or very short description
    if (!solution.description || solution.description.length < SPAM_PATTERNS.MIN_DESCRIPTION_LENGTH) {
      indicators.push('Submission has very short or missing description');
    }

    // Check for keyword stuffing or suspicious content in description
    for (const keyword of SPAM_PATTERNS.KEYWORDS) {
      if (solution.description?.toLowerCase().includes(keyword)) {
        indicators.push(`Description contains suspicious keyword: "${keyword}"`);
      }
    }

    // Check title length
    if (!solution.title || solution.title.length < SPAM_PATTERNS.MIN_TITLE_LENGTH) {
      indicators.push('Submission has very short or missing title');
    }

    // Check for repetitive content (spammy titles/descriptions)
    if (solution.title && solution.description &&
      solution.title.toLowerCase() === solution.description.toLowerCase()) {
      indicators.push('Title and description are identical');
    }

    // Check for suspicious repository metrics (if available)
    if (repoDetails) {
      // Verify repository description
      if (!repoDetails.description || repoDetails.description.length < SPAM_PATTERNS.MIN_DESCRIPTION_LENGTH) {
        indicators.push('Repository has very short or missing description');
      }

      // Check for excessive self-promotion in repository description
      for (const keyword of SPAM_PATTERNS.KEYWORDS) {
        if (repoDetails.description?.toLowerCase().includes(keyword)) {
          indicators.push(`Repository description contains suspicious keyword: "${keyword}"`);
        }
      }

      // Check for repositories that are just forks without significant changes
      if (repoDetails.fork && repoDetails.stargazers_count === 0 && repoDetails.forks_count === 0) {
        indicators.push('Repository is a fork with no stars or additional forks');
      }
    }

    return indicators;
  }

  /**
   * Additional validation specific to this agent
   */
  protected validateSolution(solution: ISolution): void {
    // Call parent validation
    super.validateSolution(solution);

    // Add GitHub-specific validation
    if (!solution.submissionUrl) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'GitHub submission URL is required',
        true,
        'MISSING_GITHUB_URL'
      );
    }

    // Check for GitHub URL pattern
    if (!solution.submissionUrl || !this.extractGitHubUrl(solution.submissionUrl)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Submission URL must be a GitHub repository',
        true,
        'INVALID_GITHUB_URL'
      );
    }
  }

  /**
   * Override the determination logic for the Spam Filtering Agent
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or review
   */
  protected determineDecision(result: ISpamFilteringResult): EvaluationDecision {
    // Immediate fail conditions
    if (result.metadata.isSpam) {
      return EvaluationDecision.FAIL;
    }

    if (!result.metadata.repositoryExists || !result.metadata.repositoryAccessible) {
      return EvaluationDecision.FAIL;
    }

    if (!result.metadata.isValid) {
      return EvaluationDecision.FAIL;
    }

    // If validation errors exist but the score is acceptable, send for review
    if (result.metadata.validationErrors.length > 0 && result.score >= 30) {
      return EvaluationDecision.REVIEW;
    }

    // Score-based decision for gray areas
    if (result.score < 30) {
      return EvaluationDecision.FAIL;
    } else if (result.score >= 30 && result.score < 70) {
      return EvaluationDecision.REVIEW;
    } else {
      return EvaluationDecision.PASS;
    }
  }
} 