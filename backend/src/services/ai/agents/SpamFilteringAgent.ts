import { AIAgentBase } from '../AIAgentBase';
import {
  ISpamFilteringResult,
  ISolution,
  EvaluationDecision,
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { ApiError } from '../../../utils/api.error';
import { HTTP_STATUS } from '../../../models/interfaces';

// Define common patterns for spam repositories
import SPAM_PATTERNS from '../../../constants/spam.patterns';
import { GitHubService, IGitHubRepoDetails } from '../../../services/github.service';

// Import LLM services
import { LLMService } from '../../llm/LLMService';
import { ILLMTextRequest, ILLMMessage } from '../../llm/interfaces/ILLMRequest';
import { ILLMService } from '../../llm/interfaces/ILLMService';
import { singleton } from 'tsyringe';
import { IChallengeContext } from '../EvaluationPipelineController';

// Interface for AI-powered spam analysis
interface IAISpamAnalysisResult {
  isSpam: boolean;
  confidence: number;
  spamIndicators: string[];
  maliciousContentDetected: boolean;
  reasoningExplanation: string;
}

// Interface for repository relevance analysis
interface IRelevanceAnalysisResult {
  isRelevant: boolean;
  relevanceScore: number; // 0-100
  matchedKeywords: string[];
  mismatchedAreas: string[];
  reasoning: string;
  confidence: number;
}

// Interface for persistent spam patterns
interface ISpamPattern {
  pattern: string;
  type: 'url' | 'content' | 'repo_name' | 'description';
  severity: 'low' | 'medium' | 'high';
  dateAdded: Date;
  occurrences: number;
  source: 'manual' | 'ai_generated';
}

// Interface for enhanced spam metadata
interface IEnhancedSpamMetadata {
  isSpam: boolean;
  isValid: boolean;
  repositoryExists: boolean;
  repositoryAccessible: boolean;
  confidence: number;
  spamIndicators: string[];
  validationErrors: string[];
  relevanceAnalysis?: IRelevanceAnalysisResult;
  contextMatchScore?: number; // 0-100
  challengeContext?: Partial<IChallengeContext>;
  adaptiveFiltering?: {
    detectedPatterns: string[];
    falsePositives: boolean;
    adjustmentsMade: boolean;
  };
}

/**
 * Spam/Bad Submission Filtering Agent
 * Acts as first-pass filter to identify spam or invalid GitHub submissions
 * Enhanced with LLM-based repository relevance analysis and context-aware filtering
 */
export class SpamFilteringAgent extends AIAgentBase<ISpamFilteringResult> {
  private static instance: SpamFilteringAgent;
  public name = 'SpamFilteringAgent';
  public description = 'Filters out spam, invalid, or irrelevant GitHub submissions using advanced LLM analysis';

  // Cache of fingerprints for duplicate detection
  private static submissionFingerprints: Map<string, number> = new Map();

  // Persistent storage of detected spam patterns
  private static spamPatternStore: Map<string, ISpamPattern> = new Map();

  // LLM service instance
  private readonly llmService: ILLMService;

  // AI model configuration
  private readonly MODEL_NAME = 'gpt-4o'; // Upgraded model for better context understanding
  private readonly MAX_TOKENS = 2000; // Increased token limit for deeper analysis
  private readonly TEMPERATURE = 0.1; // Low temperature for more deterministic results

  // Token optimization settings
  private readonly MAX_README_SIZE = 4000; // Characters
  private readonly MAX_CODE_SAMPLE_SIZE = 5000; // Characters
  private readonly MAX_FILES_TO_ANALYZE = 5;

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    super();
    this.llmService = LLMService.getInstance();
    logger.debug('SpamFilteringAgent initialized with LLMService');
  }

  /**
   * Get the singleton instance
   * @returns The SpamFilteringAgent instance
   */
  public static getInstance(): SpamFilteringAgent {
    if (!SpamFilteringAgent.instance) {
      SpamFilteringAgent.instance = new SpamFilteringAgent();
    }
    return SpamFilteringAgent.instance;
  }

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

      // Check for challenge context
      const challengeContext = solution.context?.challengeContext as IChallengeContext | undefined;

      if (!challengeContext && solution.challenge) {
        logger.warn(`Challenge context not found in solution object, but challenge ID exists`, {
          solutionId: solution._id?.toString(),
          challengeId: solution.challenge.toString()
        });
      }

      // Extract GitHub repository URL from submission
      const repoUrl = this.extractGitHubUrl(solution.submissionUrl);

      // Set up validation errors array to collect all issues
      const validationErrors: string[] = [];
      let spamIndicators: string[] = [];

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

      // Initialize enhanced metadata
      const enhancedMetadata: IEnhancedSpamMetadata = {
        isSpam: false,
        isValid: true,
        repositoryExists: true,
        repositoryAccessible: true,
        confidence: 0,
        spamIndicators: [],
        validationErrors: validationErrors,
        contextMatchScore: 0,
        challengeContext: challengeContext ? {
          challengeId: challengeContext.challengeId,
          title: challengeContext.title,
          requirements: challengeContext.requirements
          // Only include essential fields to minimize memory usage
        } : undefined,
        adaptiveFiltering: {
          detectedPatterns: [],
          falsePositives: false,
          adjustmentsMade: false
        }
      };

      // Perform relevance analysis if challenge context is available
      let relevanceAnalysis: IRelevanceAnalysisResult | undefined = undefined;
      if (challengeContext && Object.keys(challengeContext).length > 0) {
        relevanceAnalysis = await this.analyzeRepositoryRelevance(
          solution,
          owner,
          repo,
          repoDetails,
          contentAnalysis,
          challengeContext
        );

        // Add to metadata
        enhancedMetadata.relevanceAnalysis = relevanceAnalysis;
        enhancedMetadata.contextMatchScore = relevanceAnalysis.relevanceScore;

        // Add mismatched areas as spam indicators if relevance is low
        if (relevanceAnalysis.relevanceScore < 30) {
          spamIndicators.push(`Repository appears irrelevant to the challenge (score: ${relevanceAnalysis.relevanceScore})`);
          relevanceAnalysis.mismatchedAreas.forEach(area => {
            spamIndicators.push(`Challenge mismatch: ${area}`);
          });
        }
      }

      // Use AI to analyze the repository for spam, malicious content, and other issues
      try {
        const aiAnalysisResults = await this.performAISpamAnalysis(solution, owner, repo, repoDetails, contentAnalysis);

        // Add AI-detected spam indicators
        if (aiAnalysisResults.spamIndicators && aiAnalysisResults.spamIndicators.length > 0) {
          spamIndicators = [...spamIndicators, ...aiAnalysisResults.spamIndicators];
        }

        // Set confidence and spam detection from AI analysis
        enhancedMetadata.confidence = aiAnalysisResults.confidence;
        enhancedMetadata.isSpam = aiAnalysisResults.isSpam;

        // Add detected patterns to adaptive filtering
        if (enhancedMetadata.adaptiveFiltering) {
          enhancedMetadata.adaptiveFiltering.detectedPatterns = aiAnalysisResults.spamIndicators;
        }

        // Store new spam patterns if we're very confident
        if (aiAnalysisResults.isSpam && aiAnalysisResults.confidence > 85) {
          this.storeSpamPatterns(aiAnalysisResults.spamIndicators);
        }
      } catch (aiError) {
        logger.error(`Error in AI spam analysis`, {
          solutionId: solution._id?.toString(),
          error: aiError instanceof Error ? aiError.message : String(aiError)
        });

        // Set fallback confidence
        enhancedMetadata.confidence = 50;
      }

      // Calculate the final spam detection score
      let finalScore = 100; // Start with perfect score and deduct points

      // Deduct for each spam indicator based on prevalence and severity
      const uniqueSpamIndicators = [...new Set(spamIndicators)];
      enhancedMetadata.spamIndicators = uniqueSpamIndicators;

      if (uniqueSpamIndicators.length > 0) {
        // More indicators = exponentially lower score
        const spamDeduction = Math.min(80, uniqueSpamIndicators.length * 15);
        finalScore -= spamDeduction;

        // Deduct more if we have critical indicators
        if (uniqueSpamIndicators.some(i => i.toLowerCase().includes('malicious') ||
          i.toLowerCase().includes('harmful'))) {
          finalScore -= 30;
        }
      }

      // Deduct for low relevance if we have that information
      if (relevanceAnalysis && relevanceAnalysis.relevanceScore < 50) {
        const relevanceDeduction = Math.round((50 - relevanceAnalysis.relevanceScore) / 2);
        finalScore -= relevanceDeduction;
      }

      // Ensure score stays in valid range
      finalScore = Math.max(0, Math.min(100, finalScore));

      // Generate appropriate feedback based on results
      let feedback = '';

      if (finalScore < 30) {
        feedback = 'This submission has been flagged as potentially spam or irrelevant. ' +
          'Please ensure your GitHub repository contains legitimate code for this challenge.';
      } else if (finalScore < 60) {
        feedback = 'This submission may not fully match the challenge requirements. ' +
          'Please review your submission and ensure it addresses the specific challenge criteria.';
      } else {
        feedback = 'Submission passes initial validity checks. You can continue with the detailed evaluation.';
      }

      // Add repository summary
      if (repoDetails) {
        // Use owner/repo as fallback for full name if not available
        const repoFullName = `${owner}/${repo}`;

        const repoSummary = `\n\nRepository: ${repoFullName}, ` +
          `${contentAnalysis.fileCount} files, ` +
          `${repoDetails.size}KB, ` +
          `Last updated: ${new Date(repoDetails.updated_at).toDateString()}.`;

        feedback += repoSummary;
      }

      // Return the result with properly typed metadata
      return {
        score: finalScore,
        feedback,
        metadata: enhancedMetadata as ISpamFilteringResult['metadata'],
        evaluatedAt: new Date()
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error(`Error in spam filtering evaluation`, {
        solutionId: solution._id?.toString(),
        error: errorMessage,
        stack: errorStack
      });

      return {
        score: 0,
        feedback: `Error during spam filtering evaluation: ${errorMessage}`,
        metadata: {
          isSpam: false,
          isValid: false,
          repositoryExists: false,
          repositoryAccessible: false,
          confidence: 0,
          spamIndicators: [],
          validationErrors: [`Error: ${errorMessage}`]
        },
        evaluatedAt: new Date()
      };
    }
  }

  /**
   * Extract GitHub repository URL from submission
   * @param submissionUrl - Submitted URL
   * @returns Cleaned GitHub URL or null if invalid
   */
  private extractGitHubUrl(submissionUrl: string): string | null {
    // Remove whitespace and normalize
    const url = submissionUrl.trim();

    // Check if it's a GitHub URL
    const githubRegex = /^https?:\/\/(?:www\.)?github\.com\/([^\/]+)\/([^\/]+)(?:\/|$)/i;
    if (!githubRegex.test(url)) {
      return null;
    }

    // Extract the base repository URL without additional paths
    const match = url.match(githubRegex);
    if (!match || !match[1] || !match[2]) {
      return null;
    }

    return `https://github.com/${match[1]}/${match[2]}`;
  }

  /**
   * Analyze repository contents for signs of spam or invalid submissions
   * @param owner - Repository owner
   * @param repo - Repository name
   * @returns Content analysis result
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
    // Get repository contents
    const contents = await GitHubService.getRepositoryContents(owner, repo);

    // Check if it's empty
    const isEmpty = contents.length === 0;
    const fileCount = contents.length;

    // Check if it's missing a README
    const hasReadme = contents.some(file =>
      file.name.toLowerCase().includes('readme'));

    // Check if it has actual code files (not just configuration files)
    const codeExtensions = ['.js', '.ts', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb', '.cs', '.html', '.css'];
    const hasCodeFiles = contents.some(file => {
      const ext = file.name.includes('.') ? `.${file.name.split('.').pop()?.toLowerCase()}` : '';
      return codeExtensions.includes(ext);
    });

    // Check if it only has template files
    const templateFiles = [
      'license', 'license.md', 'license.txt',
      '.gitignore', '.github', 'code_of_conduct.md',
      'contributing.md', '.gitattributes', '.editorconfig'
    ];

    const isTemplateOnly = contents.every(file =>
      templateFiles.includes(file.name.toLowerCase()));

    return {
      isEmpty,
      isMissingReadme: !hasReadme,
      hasLowFileCount: fileCount < 3, // Arbitrary threshold
      isTemplateOnly,
      fileCount,
      hasCodeFiles
    };
  }

  /**
   * Track duplicate submissions by maintaining repository fingerprints
   * @param repoFingerprint - Repository fingerprint (owner/repo)
   * @returns Count of submissions for this repository
   */
  private checkDuplicateSubmission(repoFingerprint: string): number {
    // Create a count if this is the first time seeing this fingerprint
    if (!SpamFilteringAgent.submissionFingerprints.has(repoFingerprint)) {
      SpamFilteringAgent.submissionFingerprints.set(repoFingerprint, 1);
      return 1;
    }

    // Increment the count for existing fingerprints
    const count = SpamFilteringAgent.submissionFingerprints.get(repoFingerprint) || 0;
    SpamFilteringAgent.submissionFingerprints.set(repoFingerprint, count + 1);

    return count + 1;
  }

  /**
   * Detect spam indicators in repository content
   * @param solution - The solution being evaluated
   * @param repoUrl - GitHub repository URL
   * @param repoDetails - Repository details
   * @returns Array of detected spam indicators
   */
  private async detectSpamIndicators(
    solution: ISolution,
    repoUrl: string,
    repoDetails?: IGitHubRepoDetails
  ): Promise<string[]> {
    const spamIndicators: string[] = [];

    // Extract relevant content for analysis
    const title = solution.title || '';
    const description = solution.description || '';
    const repoName = repoDetails?.name || '';
    const repoDescription = repoDetails?.description || '';

    // Combine text for analysis
    const text = `${title} ${description} ${repoName} ${repoDescription}`.toLowerCase();

    // Check for spam keywords
    for (const keyword of SPAM_PATTERNS.KEYWORDS) {
      if (text.includes(keyword.toLowerCase())) {
        spamIndicators.push(`Contains spam keyword: "${keyword}"`);
      }
    }

    // Check for excessive punctuation
    if (/!{3,}|\.{4,}|\?{3,}/.test(text)) {
      spamIndicators.push('Contains excessive punctuation (!!!, ...., ???)');
    }

    // Check for ALL CAPS words (excluding common acronyms)
    const words = text.split(/\s+/);
    const allCapsWords = words.filter(word =>
      word.length > 3 &&
      word === word.toUpperCase() &&
      !SPAM_PATTERNS.COMMON_ACRONYMS.includes(word)
    );

    if (allCapsWords.length > 3) {
      spamIndicators.push('Contains excessive use of ALL CAPS words');
    }

    // Check for repeated text patterns
    if (this.hasRepeatedPatterns(text)) {
      spamIndicators.push('Contains suspicious repetitive text patterns');
    }

    // Check for URL shorteners or suspicious links
    for (const pattern of SPAM_PATTERNS.SUSPICIOUS_URL_PATTERNS) {
      if (new RegExp(pattern, 'i').test(text)) {
        spamIndicators.push('Contains suspicious URLs or link shorteners');
        break;
      }
    }

    return spamIndicators;
  }

  /**
   * Perform AI-powered spam analysis on the repository
   * Enhanced to incorporate challenge context and requirements
   * @param solution - The solution being evaluated
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param repoDetails - Repository details from GitHub
   * @param contentAnalysis - Repository content analysis
   * @returns AI spam analysis result
   */
  private async performAISpamAnalysis(
    solution: ISolution,
    owner: string,
    repo: string,
    repoDetails?: IGitHubRepoDetails,
    contentAnalysis?: any
  ): Promise<IAISpamAnalysisResult> {
    try {
      // Check if AI service is available
      if (!this.llmService) {
        throw new Error('LLM service is not available');
      }

      // Get challenge context if available
      const challengeContext = solution.context?.challengeContext as IChallengeContext | undefined;

      // Collect repository data for analysis
      const repoData = {
        owner,
        repo,
        url: `https://github.com/${owner}/${repo}`,
        title: solution.title || '',
        description: solution.description || '',
        repoName: repoDetails?.name || '',
        repoDescription: repoDetails?.description || '',
        solutionId: solution._id?.toString() || '',
        createdAt: repoDetails?.created_at ? new Date(repoDetails.created_at).toISOString() : '',
        updatedAt: repoDetails?.updated_at ? new Date(repoDetails.updated_at).toISOString() : '',
        pushedAt: repoDetails?.pushed_at ? new Date(repoDetails.pushed_at).toISOString() : '',
        stars: repoDetails?.stargazers_count || 0,
        forks: repoDetails?.forks_count || 0,
        issues: repoDetails?.open_issues_count || 0,
        fileCount: contentAnalysis?.fileCount || 0,
        hasReadme: !contentAnalysis?.isMissingReadme,
        hasCodeFiles: contentAnalysis?.hasCodeFiles,
      };

      // Get README content sample if available (with token optimization)
      let readmeSample = '';
      try {
        const readme = await GitHubService.getReadmeContent(owner, repo);
        readmeSample = readme.length > this.MAX_README_SIZE ?
          readme.substring(0, this.MAX_README_SIZE) + '...' :
          readme;
      } catch (error) {
        logger.debug(`Could not fetch README for ${owner}/${repo}`);
      }

      // Check stored spam patterns
      const matchedStoredPatterns = this.checkStoredSpamPatterns({
        repoName: repoData.repoName,
        repoDescription: repoData.repoDescription,
        readmeContent: readmeSample,
        url: repoData.url
      });

      // Get code samples from the repository (with token optimization)
      let codeSamples: string[] = [];
      let fileList: string[] = [];
      try {
        const files = await GitHubService.getRepositoryFiles(owner, repo, this.MAX_FILES_TO_ANALYZE);
        fileList = files.map(f => f.path);

        for (const file of files) {
          if (file.content) {
            const truncatedContent = file.content.length > this.MAX_CODE_SAMPLE_SIZE ?
              file.content.substring(0, this.MAX_CODE_SAMPLE_SIZE) + '...' :
              file.content;

            codeSamples.push(`File: ${file.path}\n${truncatedContent}`);
          }
        }
      } catch (error) {
        logger.debug(`Could not fetch code samples for ${owner}/${repo}`);
      }

      // Create the system prompt
      const systemPrompt = `You are a specialized spam detection AI tasked with analyzing GitHub repositories for spam, malicious content, or low-quality submissions. 
Your job is to determine whether a GitHub repository submission is legitimate or potentially spam/harmful.

Characteristics of spam or problematic repositories:
1. Empty or nearly empty repositories with minimal content
2. Repositories containing malicious code, phishing attempts, or scams
3. Repositories with keyword stuffing, excessive marketing language, or unrelated to the stated purpose
4. Repositories that are forks with minimal or no changes
5. Repositories containing harmful, illegal, or offensive content
6. Repositories that appear to be automated or AI-generated without human refinement
7. Repositories with plagiarized code without proper attribution
8. Repositories that are completely unrelated to the challenge requirements

Provide your evaluation in a structured JSON format with the following fields:
- isSpam: boolean indicating if this is spam or not
- confidence: number from 0-100 indicating confidence level
- spamIndicators: array of strings describing specific spam indicators found
- maliciousContentDetected: boolean indicating if potentially harmful content was found
- reasoningExplanation: brief explanation of your reasoning

Be thorough but objective in your analysis. When in doubt, err on the side of caution.`;

      // Build challenge context section if available
      let challengeSection = '';
      if (challengeContext) {
        challengeSection = `
Challenge Information:
- Title: ${challengeContext.title}
- Description: ${challengeContext.description || 'No description provided'}
${challengeContext.category ? `- Category: ${challengeContext.category.join(', ')}` : ''}
${challengeContext.difficulty ? `- Difficulty: ${challengeContext.difficulty}` : ''}
${challengeContext.status ? `- Status: ${challengeContext.status}` : ''}
${challengeContext.deadline ? `- Deadline: ${challengeContext.deadline.toISOString()}` : ''}

Requirements:
${challengeContext.requirements.map(req => 
  `- ${req}`
).join('\n')}
`;
      }

      // Build context message with repository data
      const contextMessage = `
${challengeSection}

Repository Information:
- Owner: ${repoData.owner}
- Repo: ${repoData.repo}
- URL: ${repoData.url}
- Title: ${repoData.title}
- Description: ${repoData.description}
- Repository Name: ${repoData.repoName}
- Repository Description: ${repoData.repoDescription}
- Created: ${repoData.createdAt}
- Last Updated: ${repoData.updatedAt}
- Last Push: ${repoData.pushedAt}
- Stars: ${repoData.stars}
- Forks: ${repoData.forks}
- Open Issues: ${repoData.issues}
- File Count: ${repoData.fileCount}
- Has README: ${repoData.hasReadme}
- Has Code Files: ${repoData.hasCodeFiles}

File List:
${fileList.join('\n')}

${matchedStoredPatterns.length > 0 ?
          `Known Spam Patterns Detected:\n${matchedStoredPatterns.join('\n')}\n\n` : ''}

${readmeSample ? `README Sample:\n${readmeSample}\n\n` : ''}

${codeSamples.length > 0 ?
          `Code Samples (${Math.min(codeSamples.length, 2)} of ${codeSamples.length}):\n${codeSamples.slice(0, 2).join('\n\n').substring(0, 3000)}` :
          'No code samples available'}`;

      // Prepare the user message
      const userMessage = `Analyze this GitHub repository submission and determine if it's legitimate or spam/malicious. ${challengeContext ? 'Pay close attention to whether it appears to address the challenge requirements.' : ''
        } Provide your findings in the specified JSON format.`;

      // Prepare the request
      const messages: ILLMMessage[] = [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: contextMessage },
        { role: 'user', content: userMessage }
      ];

      const request: ILLMTextRequest = {
        model: this.MODEL_NAME,
        messages,
        temperature: this.TEMPERATURE,
        maxTokens: this.MAX_TOKENS,
        jsonMode: true,
        metadata: {
          source: "SpamFilteringAgent",
          operation: "performAISpamAnalysis",
          challengeId: challengeContext?.challengeId || 'unknown',
          solutionId: solution._id?.toString() || 'unknown'
        }
      };

      // Make the API call
      const response = await this.llmService.generateText(request);

      // Parse and validate the response
      try {
        const result: IAISpamAnalysisResult = JSON.parse(response.text);

        // Ensure all required fields are present
        if (typeof result.isSpam !== 'boolean' ||
          typeof result.confidence !== 'number' ||
          !Array.isArray(result.spamIndicators) ||
          typeof result.maliciousContentDetected !== 'boolean' ||
          typeof result.reasoningExplanation !== 'string') {

          throw new Error('Invalid response format from AI');
        }

        // Add stored pattern matches if they weren't already included
        if (matchedStoredPatterns.length > 0) {
          const existingPatterns = new Set(result.spamIndicators);
          for (const pattern of matchedStoredPatterns) {
            if (!existingPatterns.has(pattern)) {
              result.spamIndicators.push(pattern);
            }
          }

          // If we found stored patterns, increase confidence and ensure isSpam is true
          if (matchedStoredPatterns.length >= 2) {
            result.isSpam = true;
            result.confidence = Math.max(result.confidence, 90);
          }
        }

        return result;
      } catch (parseError) {
        logger.error('Failed to parse AI response', {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          responseText: response.text
        });

        // Return a default structure on parsing error
        return {
          isSpam: matchedStoredPatterns.length > 1, // Flag as spam if multiple stored patterns matched
          confidence: matchedStoredPatterns.length > 1 ? 85 : 0,
          spamIndicators: matchedStoredPatterns.length > 0 ? matchedStoredPatterns : [],
          maliciousContentDetected: false,
          reasoningExplanation: 'Failed to parse AI analysis results'
        };
      }
    } catch (error) {
      logger.error('Error in AI spam analysis', {
        error: error instanceof Error ? error.message : String(error),
        solutionId: solution._id?.toString()
      });

      // Fall back to rule-based approach on error
      return {
        isSpam: false,
        confidence: 0,
        spamIndicators: [],
        maliciousContentDetected: false,
        reasoningExplanation: `AI analysis error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check for repeated text patterns, which may indicate spam
   * @param text - Text to check
   * @returns Whether suspicious repeated patterns were found
   */
  private hasRepeatedPatterns(text: string): boolean {
    // Check for repeated phrases (3+ words repeated at least twice)
    const words = text.split(/\s+/);
    if (words.length < 6) return false;

    for (let i = 0; i < words.length - 5; i++) {
      const phrase = words.slice(i, i + 3).join(' ');
      if (phrase.length < 10) continue; // Skip short phrases

      // Look for the same phrase later in the text
      for (let j = i + 3; j < words.length - 2; j++) {
        const checkPhrase = words.slice(j, j + 3).join(' ');
        if (phrase === checkPhrase) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Override of the base validation method to include spam-specific validation
   * @param solution - The solution to validate
   */
  protected validateSolution(solution: ISolution): void {
    // Call parent validation first
    super.validateSolution(solution);

    // Spam-specific validation
    if (!solution.submissionUrl) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Submission URL is required for spam analysis',
        true,
        'MISSING_SUBMISSION_URL'
      );
    }

    // Validate URL format
    const githubRegex = /^https?:\/\/(?:www\.)?github\.com\/([^\/]+)\/([^\/]+)(?:\/|$)/i;
    if (!githubRegex.test(solution.submissionUrl)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Submission URL must be a valid GitHub repository URL',
        true,
        'INVALID_GITHUB_URL'
      );
    }
  }

  /**
   * Override determineDecision to handle enhanced decision logic
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or request review
   */
  protected determineDecision(result: ISpamFilteringResult): EvaluationDecision {
    // Get the enhanced metadata if available
    const enhancedMetadata = result.metadata as IEnhancedSpamMetadata;

    // Hard failure cases - always return FAIL
    if (!result.metadata.repositoryExists || !result.metadata.repositoryAccessible) {
      return EvaluationDecision.FAIL;
    }

    // If we detected that this is spam and we're confident, return FAIL
    if (result.metadata.isSpam && result.metadata.confidence > 75) {
      return EvaluationDecision.FAIL;
    }

    // Check relevance to challenge if we have that analysis
    if (enhancedMetadata.relevanceAnalysis) {
      // If extremely low relevance, fail the submission
      if (enhancedMetadata.relevanceAnalysis.relevanceScore < 20 &&
        enhancedMetadata.relevanceAnalysis.confidence > 70) {
        logger.info(`Failing submission due to extremely low relevance score`, {
          relevanceScore: enhancedMetadata.relevanceAnalysis.relevanceScore,
          confidence: enhancedMetadata.relevanceAnalysis.confidence,
          challengeId: enhancedMetadata.challengeContext?.challengeId || 'unknown'
        });
        return EvaluationDecision.FAIL;
      }

      // If moderately low relevance, request review
      if (enhancedMetadata.relevanceAnalysis.relevanceScore < 40 &&
        enhancedMetadata.relevanceAnalysis.confidence > 60) {
        logger.info(`Requesting review due to moderately low relevance score`, {
          relevanceScore: enhancedMetadata.relevanceAnalysis.relevanceScore,
          confidence: enhancedMetadata.relevanceAnalysis.confidence,
          challengeId: enhancedMetadata.challengeContext?.challengeId || 'unknown'
        });
        return EvaluationDecision.REVIEW;
      }
    }

    // Score-based decisions
    if (result.score < 30) {
      return EvaluationDecision.FAIL;
    } else if (result.score < 60) {
      return EvaluationDecision.REVIEW;
    } else {
      return EvaluationDecision.PASS;
    }
  }

  /**
   * Analyze repository relevance to the challenge context
   * @param solution - The solution being evaluated
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param repoDetails - Repository details from GitHub
   * @param contentAnalysis - Repository content analysis
   * @param challengeContext - Challenge context
   * @returns Repository relevance analysis result
   */
  private async analyzeRepositoryRelevance(
    solution: ISolution,
    owner: string,
    repo: string,
    repoDetails?: IGitHubRepoDetails,
    contentAnalysis?: any,
    challengeContext?: IChallengeContext
  ): Promise<IRelevanceAnalysisResult> {
    try {
      // Default result if analysis fails
      const defaultResult: IRelevanceAnalysisResult = {
        isRelevant: true,
        relevanceScore: 50,
        matchedKeywords: [],
        mismatchedAreas: [],
        reasoning: "Couldn't perform detailed relevance analysis",
        confidence: 50
      };

      // If no challenge context or LLM service, return default
      if (!challengeContext || !this.llmService) {
        return defaultResult;
      }

      logger.debug(`Analyzing repository relevance to challenge`, {
        solutionId: solution._id?.toString(),
        repo: `${owner}/${repo}`,
        challengeId: challengeContext.challengeId
      });

      // Gather data about the repository
      const repoData = {
        owner,
        repo,
        url: `https://github.com/${owner}/${repo}`,
        title: solution.title || '',
        description: solution.description || '',
        repoName: repoDetails?.name || '',
        repoDescription: repoDetails?.description || '',
        createdAt: repoDetails?.created_at ? new Date(repoDetails.created_at).toISOString() : '',
        updatedAt: repoDetails?.updated_at ? new Date(repoDetails.updated_at).toISOString() : '',
        fileCount: contentAnalysis?.fileCount || 0,
        hasReadme: !contentAnalysis?.isMissingReadme,
        hasCodeFiles: contentAnalysis?.hasCodeFiles
      };


      // Get README content sample if available
      let readmeSample = '';
      try {
        const readme = await GitHubService.getReadmeContent(owner, repo);
        readmeSample = readme.length > this.MAX_README_SIZE ?
          readme.substring(0, this.MAX_README_SIZE) + '...' :
          readme;
      } catch (error) {
        logger.debug(`Could not fetch README for ${owner}/${repo}`);
      }

      // Get code samples from the repository 
      let codeSamples: string[] = [];
      let fileList: string[] = [];
      try {
        const files = await GitHubService.getRepositoryFiles(owner, repo, this.MAX_FILES_TO_ANALYZE);
        fileList = files.map(f => f.path);

        for (const file of files) {
          if (file.content) {
            const truncatedContent = file.content.length > this.MAX_CODE_SAMPLE_SIZE ?
              file.content.substring(0, this.MAX_CODE_SAMPLE_SIZE) + '...' :
              file.content;

            codeSamples.push(`File: ${file.path}\n${truncatedContent}`);
          }
        }
      } catch (error) {
        logger.debug(`Could not fetch code samples for ${owner}/${repo}`);
      }

      // Create system prompt for relevance analysis
      const systemPrompt = `You are an expert evaluator determining if a GitHub repository is relevant to a coding challenge.
Your task is to analyze the repository contents against the challenge requirements and determine if the submission is relevant.

A repository is relevant if:
1. It addresses the main challenge objectives
2. It includes the required file types, libraries, or frameworks 
3. It appears to be a genuine attempt to complete the challenge rather than unrelated code

Format your response as a valid JSON object with the following fields:
- isRelevant: boolean indicating if the repository is relevant to the challenge
- relevanceScore: number from 0-100 representing how relevant the repository is
- matchedKeywords: array of strings listing keywords or requirements that match
- mismatchedAreas: array of strings listing areas where the repository doesn't match challenge requirements
- reasoning: string explaining your assessment
- confidence: number from 0-100 indicating your confidence in this assessment`;

      // Prepare the context message with repository and challenge data
      const contextMessage = `
Challenge Information:
- Title: ${challengeContext.title}
- Description: ${challengeContext.description || 'No description provided'}
- Category: ${challengeContext.category?.join(', ') || 'Not specified'}
- Difficulty: ${challengeContext.difficulty || 'Not specified'}

Requirements:
${challengeContext.requirements.map(req => `- ${req}`).join('\n')}

${challengeContext.tags?.length ? `Tags: ${challengeContext.tags.join(', ')}\n` : ''}

Repository Information:
- Owner: ${repoData.owner}
- Repo: ${repoData.repo}
- URL: ${repoData.url}
- Repository Name: ${repoData.repoName}
- Repository Description: ${repoData.repoDescription || 'No description'}
- File Count: ${repoData.fileCount}
- Has README: ${repoData.hasReadme}
- Has Code Files: ${repoData.hasCodeFiles}

File List:
${fileList.join('\n')}

${readmeSample ? `README Sample:\n${readmeSample}\n\n` : ''}

${codeSamples.length > 0 ?
          `Code Samples (${Math.min(codeSamples.length, 2)} of ${codeSamples.length}):\n${codeSamples.slice(0, 2).join('\n\n').substring(0, 3000)}` :
          'No code samples available'}`;

      // Prepare the user message
      const userMessage = `Analyze this GitHub repository and determine if it is relevant to the coding challenge. Provide your findings in the specified JSON format.`;

      // Prepare the LLM request
      const messages: ILLMMessage[] = [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: contextMessage },
        { role: 'user', content: userMessage }
      ];

      const request: ILLMTextRequest = {
        model: this.MODEL_NAME,
        messages,
        temperature: this.TEMPERATURE,
        maxTokens: this.MAX_TOKENS,
        jsonMode: true,
        metadata: {
          source: "SpamFilteringAgent",
          operation: "analyzeRepositoryRelevance",
          challengeId: challengeContext.challengeId,
          solutionId: solution._id?.toString() || 'unknown'
        }
      };

      // Make the API call
      const response = await this.llmService.generateText(request);

      // Parse and validate the response
      try {
        const result: IRelevanceAnalysisResult = JSON.parse(response.text);

        // Basic validation
        if (typeof result.isRelevant !== 'boolean' ||
          typeof result.relevanceScore !== 'number' ||
          !Array.isArray(result.matchedKeywords) ||
          !Array.isArray(result.mismatchedAreas) ||
          typeof result.reasoning !== 'string' ||
          typeof result.confidence !== 'number') {

          logger.warn(`Invalid response format from relevance analysis`, {
            solutionId: solution._id?.toString(),
            responseText: response.text.substring(0, 200) + "..."
          });

          return defaultResult;
        }

        // Ensure values are in valid ranges
        result.relevanceScore = Math.max(0, Math.min(100, result.relevanceScore));
        result.confidence = Math.max(0, Math.min(100, result.confidence));

        logger.info(`Repository relevance analysis complete`, {
          solutionId: solution._id?.toString(),
          repo: `${owner}/${repo}`,
          isRelevant: result.isRelevant,
          relevanceScore: result.relevanceScore,
          confidence: result.confidence
        });

        return result;
      } catch (parseError) {
        logger.error(`Failed to parse relevance analysis response`, {
          solutionId: solution._id?.toString(),
          error: parseError instanceof Error ? parseError.message : String(parseError),
          responseText: response.text.substring(0, 200) + "..."
        });

        return defaultResult;
      }
    } catch (error) {
      logger.error(`Error in repository relevance analysis`, {
        solutionId: solution._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });

      return {
        isRelevant: true,
        relevanceScore: 50,
        matchedKeywords: [],
        mismatchedAreas: [],
        reasoning: `Error during relevance analysis: ${error instanceof Error ? error.message : 'Unknown error'}`,
        confidence: 0
      };
    }
  }

  /**
   * Store and update spam patterns for future detection
   * @param spamIndicators - Array of spam indicators to store
   */
  private storeSpamPatterns(spamIndicators: string[]): void {
    try {
      // Skip if no indicators
      if (!spamIndicators || spamIndicators.length === 0) {
        return;
      }

      const now = new Date();

      // Process each indicator
      for (const indicator of spamIndicators) {
        // Generate a key for the spam pattern
        const normalizedIndicator = indicator
          .toLowerCase()
          .trim()
          .replace(/\s+/g, ' ');

        if (normalizedIndicator.length < 5) {
          continue; // Skip very short indicators
        }

        // Determine pattern type
        let patternType: 'url' | 'content' | 'repo_name' | 'description' = 'content';
        if (normalizedIndicator.includes('url') || normalizedIndicator.includes('http')) {
          patternType = 'url';
        } else if (normalizedIndicator.includes('repository name') || normalizedIndicator.includes('repo name')) {
          patternType = 'repo_name';
        } else if (normalizedIndicator.includes('description')) {
          patternType = 'description';
        }

        // Determine severity
        let severity: 'low' | 'medium' | 'high' = 'medium';
        if (normalizedIndicator.includes('malicious') ||
          normalizedIndicator.includes('harmful') ||
          normalizedIndicator.includes('phishing')) {
          severity = 'high';
        } else if (normalizedIndicator.includes('suspicious') ||
          normalizedIndicator.includes('spam')) {
          severity = 'medium';
        } else {
          severity = 'low';
        }

        // Check if pattern already exists
        if (SpamFilteringAgent.spamPatternStore.has(normalizedIndicator)) {
          // Increment occurrence count
          const existingPattern = SpamFilteringAgent.spamPatternStore.get(normalizedIndicator)!;
          existingPattern.occurrences += 1;
          SpamFilteringAgent.spamPatternStore.set(normalizedIndicator, existingPattern);
        } else {
          // Add new pattern
          const newPattern: ISpamPattern = {
            pattern: normalizedIndicator,
            type: patternType,
            severity,
            dateAdded: now,
            occurrences: 1,
            source: 'ai_generated'
          };

          SpamFilteringAgent.spamPatternStore.set(normalizedIndicator, newPattern);
        }
      }

      // Log the state of the pattern store
      logger.debug(`Spam pattern store updated`, {
        totalPatterns: SpamFilteringAgent.spamPatternStore.size,
        newIndicators: spamIndicators.length
      });
    } catch (error) {
      logger.error(`Error storing spam patterns`, {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Check stored spam patterns against repository data
   * @param repoData - Repository data to check
   * @returns Matching spam patterns
   */
  private checkStoredSpamPatterns(repoData: {
    repoName?: string;
    repoDescription?: string;
    readmeContent?: string;
    url?: string;
  }): string[] {
    const matchedPatterns: string[] = [];

    try {
      // Skip if no patterns stored
      if (SpamFilteringAgent.spamPatternStore.size === 0) {
        return matchedPatterns;
      }

      // Check each pattern against appropriate fields
      for (const [key, pattern] of SpamFilteringAgent.spamPatternStore.entries()) {
        // Skip patterns with low occurrence count (less reliable)
        if (pattern.occurrences < 2) {
          continue;
        }

        let shouldCheck = false;
        let field = '';

        switch (pattern.type) {
          case 'url':
            shouldCheck = !!repoData.url;
            field = repoData.url || '';
            break;
          case 'repo_name':
            shouldCheck = !!repoData.repoName;
            field = repoData.repoName || '';
            break;
          case 'description':
            shouldCheck = !!repoData.repoDescription;
            field = repoData.repoDescription || '';
            break;
          case 'content':
            shouldCheck = !!repoData.readmeContent;
            field = repoData.readmeContent || '';
            break;
        }

        // Check if pattern exists in the field
        if (shouldCheck && field.toLowerCase().includes(pattern.pattern.toLowerCase())) {
          // Add context to the matched pattern
          matchedPatterns.push(`${pattern.pattern} (${pattern.severity} severity)`);
        }
      }
    } catch (error) {
      logger.error(`Error checking stored spam patterns`, {
        error: error instanceof Error ? error.message : String(error)
      });
    }

    return matchedPatterns;
  }
}

// Export singleton instance
export const spamFilteringAgent = SpamFilteringAgent.getInstance(); 