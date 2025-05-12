import { AIAgentBase } from '../AIAgentBase';
import {
  IRequirementsComplianceResult,
  ISolution,
  EvaluationDecision
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { GitHubService, IRepositoryStructure } from '../../../services/github.service';
import { commonTechnologies } from '../../../constants/common.tech.things';
import { LLMService } from '../../llm/LLMService';
import { ILLMTextRequest, ILLMMessage } from '../../llm/interfaces/ILLMRequest';
import { ILLMService } from '../../llm/interfaces/ILLMService';
import * as path from 'path';
import { IChallengeContext } from '../EvaluationPipelineController';
import { ChallengeDifficulty } from '../../../models/interfaces';

// Interface for our internal structured requirements
interface IStructuredRequirement {
  id: string;
  name: string;
  description: string;
  type: 'file' | 'package' | 'structure' | 'feature' | 'quality' | 'other';
  importance: 'critical' | 'important' | 'optional';
  filePath?: string;
  filePattern?: string;
  extensions?: string[];
  packageName?: string; 
  packageType?: 'npm' | 'python' | 'ruby' | 'other';
}

// Interface for AI-powered requirement verification result
interface IAIRequirementVerificationResult {
  requirementId: string;
  satisfied: boolean;
  confidence: number;
  evidenceFound: string[];
  explanationForUser: string;
  alternativeSuggestion?: string;
}

/**
 * Requirements Compliance Agent
 * Validates that GitHub submissions meet challenge requirements
 * Uses Claude 3.7 to enhance requirement validation
 */
export class RequirementsComplianceAgent extends AIAgentBase<IRequirementsComplianceResult> {
  private static instance: RequirementsComplianceAgent;
  public name = 'RequirementsComplianceAgent';
  public description = 'Verifies challenge requirements adherence in GitHub submissions with enhanced AI analysis';

  // LLM service instance
  private readonly llmService: ILLMService;

  // AI model configuration for standard analysis
  private readonly MODEL_NAME = 'gpt-4o-mini';
  private readonly MAX_TOKENS = 2000;
  private readonly TEMPERATURE = 0.2; // Low temperature for more deterministic reasoning

  // AI model configuration for deeper analysis (used in subsequent passes)
  private readonly DEEP_ANALYSIS_MODEL_NAME = 'gpt-4o'; // Higher capability model
  private readonly DEEP_ANALYSIS_MAX_TOKENS = 4000; // More tokens for thorough analysis
  private readonly DEEP_ANALYSIS_TEMPERATURE = 0.1; // Lower temperature for more precision

  // Token optimization settings for standard analysis
  private readonly MAX_CHUNK_SIZE = 8000; // Characters per chunk for code analysis
  private readonly MAX_FILES_TO_ANALYZE = 15; // Maximum number of files to analyze
  private readonly MAX_CHUNK_COUNT = 10; // Maximum number of chunks to analyze

  // Token optimization settings for deeper analysis
  private readonly DEEP_ANALYSIS_MAX_CHUNK_SIZE = 12000; // Larger chunks for more context
  private readonly DEEP_ANALYSIS_MAX_FILES = 25; // More files to analyze
  private readonly DEEP_ANALYSIS_MAX_CHUNK_COUNT = 15; // More chunks to analyze

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    super();
    this.llmService = LLMService.getInstance();
    logger.debug('RequirementsComplianceAgent initialized with LLMService');
  }

  /**
   * Get the singleton instance
   * @returns The RequirementsComplianceAgent instance
   */
  public static getInstance(): RequirementsComplianceAgent {
    if (!RequirementsComplianceAgent.instance) {
      RequirementsComplianceAgent.instance = new RequirementsComplianceAgent();
    }
    return RequirementsComplianceAgent.instance;
  }

  /**
   * Evaluate a GitHub solution for requirements compliance
   * @param solution - The solution to evaluate
   * @returns Evaluation result with score and detailed feedback
   */
  public async evaluateInternal(solution: ISolution): Promise<IRequirementsComplianceResult> {
    try {
      // Get the challenge context from the solution
      const challengeContext = solution.context?.challengeContext as IChallengeContext | undefined;
      
      if (!challengeContext) {
        logger.warn(`Challenge context not found for solution in requirements check`, {
          solutionId: solution._id?.toString()
        });

        return this.createErrorResult(
          'Unable to verify requirements compliance due to missing challenge context.'
        );
      }

      // Check if this is a deeper analysis pass
      const isDeepAnalysisMode = !!solution.context?.deeperAnalysisMode;
      
      logger.info(`Starting requirements compliance evaluation ${isDeepAnalysisMode ? '(DEEP ANALYSIS MODE)' : ''}`, {
        solutionId: solution._id?.toString(),
        challengeId: challengeContext.challengeId,
        deepAnalysisMode: isDeepAnalysisMode
      });

      // Extract GitHub repository information
      const repoInfo = await this.extractGitHubRepoInfo(solution.submissionUrl);

      logger.debug(`Analyzing repository structure for requirements compliance`, {
        solutionId: solution._id?.toString(),
        repository: `${repoInfo.owner}/${repoInfo.repo}`,
        challengeId: challengeContext.challengeId
      });

      // Analyze repository structure using GitHubService
      const repoStructure = await GitHubService.analyzeRepositoryStructure(repoInfo.owner, repoInfo.repo);

      // Extract structured requirements from the challenge context
      const requirements = this.extractStructuredRequirements(challengeContext);

      logger.debug(`Extracted ${requirements.length} structured requirements from challenge context`, {
        solutionId: solution._id?.toString(),
        challengeId: challengeContext.challengeId
      });

      // Verify each requirement using rule-based analysis first
      const ruleBasedResults = await this.verifyRequirements(repoInfo, repoStructure, requirements);

      // In deep analysis mode, we always use AI to verify all requirements
      // In standard mode, we only use AI for complex or critical requirements
      const needsAIVerification = isDeepAnalysisMode ? true : this.shouldUseAIVerification(requirements, ruleBasedResults);

      let finalRequirementResults = ruleBasedResults;

      if (needsAIVerification) {
        try {
          logger.info(`Using AI verification for ${isDeepAnalysisMode ? 'all' : 'complex'} requirements (mode: ${isDeepAnalysisMode ? 'deep' : 'standard'})`, {
            solutionId: solution._id?.toString(),
            repository: `${repoInfo.owner}/${repoInfo.repo}`,
            requirements: requirements.length
          });

          // Prepare code chunks for AI analysis
          // In deep analysis mode, we analyze more files and larger chunks
          const codeChunks = await this.prepareCodeChunksForAnalysis(
            repoInfo.owner, 
            repoInfo.repo,
            isDeepAnalysisMode ? this.DEEP_ANALYSIS_MAX_FILES : this.MAX_FILES_TO_ANALYZE,
            isDeepAnalysisMode ? this.DEEP_ANALYSIS_MAX_CHUNK_SIZE : this.MAX_CHUNK_SIZE,
            isDeepAnalysisMode ? this.DEEP_ANALYSIS_MAX_CHUNK_COUNT : this.MAX_CHUNK_COUNT
          );

          // Select requirements for AI verification
          // In deep analysis mode, we verify all requirements with AI
          const requirementsForAI = isDeepAnalysisMode ? 
            requirements : 
            this.selectRequirementsForAIVerification(requirements, ruleBasedResults);

          // Use AI to verify requirements
          const aiVerificationResults = await this.verifyRequirementsWithAI(
            requirementsForAI,
            ruleBasedResults,
            codeChunks,
            repoStructure,
            challengeContext,
            isDeepAnalysisMode
          );

          // Blend rule-based and AI verification results
          // In deep analysis mode, AI results are given higher priority
          finalRequirementResults = this.blendVerificationResults(
            ruleBasedResults,
            aiVerificationResults,
            isDeepAnalysisMode
          );

          logger.info(`AI verification completed (mode: ${isDeepAnalysisMode ? 'deep' : 'standard'})`, {
            solutionId: solution._id?.toString(),
            requirementsAnalyzed: requirementsForAI.length,
            aiVerifiedCount: aiVerificationResults.length
          });
        } catch (error) {
          // If AI verification fails, log the error but continue with rule-based results
          logger.error(`Error in AI requirements verification, falling back to rule-based results`, {
            solutionId: solution._id?.toString(),
            error: error instanceof Error ? error.message : String(error),
            trace: error instanceof Error ? error.stack : undefined
          });

          // Continue with rule-based results
          finalRequirementResults = ruleBasedResults;
        }
      }

      // Calculate scores and generate feedback
      const [score, feedback, metadata] = this.calculateScoresAndFeedback(
        finalRequirementResults,
        repoStructure,
        solution.description || '',
        challengeContext,
        isDeepAnalysisMode
      );

      logger.info(`Requirements compliance evaluation complete (mode: ${isDeepAnalysisMode ? 'deep' : 'standard'})`, {
        solutionId: solution._id?.toString(),
        repository: `${repoInfo.owner}/${repoInfo.repo}`,
        score,
        requirementsMet: metadata.requirementsSatisfied,
        totalRequirements: metadata.totalRequirements,
        usedAI: needsAIVerification,
        deepAnalysisMode: isDeepAnalysisMode
      });

      // Add deep analysis flag to metadata for tracking
      const enhancedMetadata = {
        ...metadata,
        evaluationMode: isDeepAnalysisMode ? 'deep' : 'standard',
        confidenceLevel: isDeepAnalysisMode ? 'high' : 'standard'
      };

      return {
        score,
        feedback,
        metadata: enhancedMetadata,
        evaluatedAt: new Date()
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error in requirements compliance evaluation`, {
        solutionId: solution._id?.toString(),
        submissionUrl: solution.submissionUrl,
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined
      });

      return this.createErrorResult(
        `Error evaluating requirements compliance: ${errorMessage}`
      );
    }
  }

  /**
   * Determine if we should use AI verification for requirements
   * @param requirements - Requirements to verify
   * @param ruleBasedResults - Results from rule-based verification
   * @returns Boolean indicating if AI verification is needed
   */
  private shouldUseAIVerification(
    requirements: IStructuredRequirement[],
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>
  ): boolean {
    // Check if there are complex requirements that need AI verification
    const complexRequirementTypes = ['feature', 'other', 'quality'];
    const hasComplexRequirements = requirements.some(req =>
      complexRequirementTypes.includes(req.type)
    );

    // Check if there are critical requirements
    const hasCriticalRequirements = requirements.some(req =>
      req.importance === 'critical'
    );

    // Check if there are ambiguous results (details containing "cannot be automatically verified")
    const hasAmbiguousResults = ruleBasedResults.some(result =>
      result.details.includes('cannot be automatically verified')
    );

    // Use AI verification if there are complex or critical requirements or ambiguous results
    return hasComplexRequirements || hasCriticalRequirements || hasAmbiguousResults;
  }

  /**
   * Prepare code chunks for AI analysis
   * This function chunks the code repository content into manageable pieces
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param maxFiles - Maximum number of files to analyze
   * @param maxChunkSize - Maximum size of each chunk in characters
   * @param maxChunks - Maximum number of chunks to return
   * @returns Array of code chunks
   */
  private async prepareCodeChunksForAnalysis(
    owner: string,
    repo: string,
    maxFiles: number = this.MAX_FILES_TO_ANALYZE,
    maxChunkSize: number = this.MAX_CHUNK_SIZE,
    maxChunks: number = this.MAX_CHUNK_COUNT
  ): Promise<Array<{
    content: string;
    fileCount: number;
    totalSize: number;
    description: string;
  }>> {
    try {
      logger.debug(`Preparing code chunks for analysis`, { 
        owner, 
        repo,
        maxFiles,
        maxChunkSize,
        maxChunks
      });

      // Get files from repository
      const files = await GitHubService.getRepositoryFiles(owner, repo, maxFiles);

      // Sort files by importance (prioritize certain file types)
      const prioritizedFiles = this.prioritizeFilesForAnalysis(files);

      // Create chunks
      const chunks: Array<{
        content: string;
        fileCount: number;
        totalSize: number;
        description: string;
      }> = [];

      let currentChunk = '';
      let currentChunkFiles: string[] = [];
      let currentChunkSize = 0;

      for (const file of prioritizedFiles) {
        // Skip very large files
        if (file.content.length > maxChunkSize) {
          // For large files, take just the beginning and end
          const beginning = file.content.substring(0, maxChunkSize / 2);
          const end = file.content.substring(file.content.length - maxChunkSize / 2);

          const trimmedContent = `File: ${file.path} (TRUNCATED - showing first and last parts of file)\n\n${beginning}\n\n[...file truncated...]\n\n${end}`;

          // If this is a large and important file, make it its own chunk
          chunks.push({
            content: trimmedContent,
            fileCount: 1,
            totalSize: trimmedContent.length,
            description: `Large file: ${file.path}`
          });

          continue;
        }

        // Format the file content with path
        const formattedFile = `File: ${file.path}\n\n${file.content}\n\n`;

        // Check if adding this file would exceed the chunk size
        if (currentChunk.length + formattedFile.length > maxChunkSize && currentChunk.length > 0) {
          // Save current chunk and start a new one
          chunks.push({
            content: currentChunk,
            fileCount: currentChunkFiles.length,
            totalSize: currentChunkSize,
            description: `Contains ${currentChunkFiles.length} files: ${currentChunkFiles.join(', ')}`
          });

          currentChunk = '';
          currentChunkFiles = [];
          currentChunkSize = 0;
        }

        // Add file to current chunk
        currentChunk += formattedFile;
        currentChunkFiles.push(file.path);
        currentChunkSize += formattedFile.length;
      }

      // Add the last chunk if it has content
      if (currentChunk.length > 0) {
        chunks.push({
          content: currentChunk,
          fileCount: currentChunkFiles.length,
          totalSize: currentChunkSize,
          description: `Contains ${currentChunkFiles.length} files: ${currentChunkFiles.join(', ')}`
        });
      }

      // Limit the number of chunks
      const finalChunks = chunks.slice(0, maxChunks);

      logger.debug(`Created ${finalChunks.length} code chunks for analysis`, {
        owner,
        repo,
        totalFiles: files.length,
        chunksCreated: finalChunks.length,
        totalChunkSize: finalChunks.reduce((sum, chunk) => sum + chunk.totalSize, 0)
      });

      return finalChunks;
    } catch (error) {
      logger.error(`Error preparing code chunks`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });

      // Return empty array to allow fallback to rule-based verification
      return [];
    }
  }

  /**
   * Prioritize files for analysis based on importance to requirements
   * @param files - Array of files with content
   * @returns Prioritized array of files
   */
  private prioritizeFilesForAnalysis(files: Array<{ path: string; content: string }>): Array<{ path: string; content: string }> {
    // Prioritize files based on importance:
    // 1. README and documentation files
    // 2. Package/dependency files
    // 3. Source code files
    // 4. Configuration files
    // 5. Others

    const getFilePriority = (file: { path: string; content: string }): number => {
      const fileName = path.basename(file.path).toLowerCase();
      const extension = path.extname(file.path).toLowerCase();

      // README and documentation files
      if (fileName.includes('readme') || fileName.includes('documentation')) {
        return 1;
      }

      // Package/dependency files
      if (
        fileName === 'package.json' ||
        fileName === 'requirements.txt' ||
        fileName === 'gemfile' ||
        fileName === 'build.gradle' ||
        fileName === 'pom.xml'
      ) {
        return 2;
      }

      // Source code files (use common extensions)
      const sourceExtensions = ['.js', '.ts', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb', '.cs', '.html', '.css'];
      if (sourceExtensions.includes(extension)) {
        return 3;
      }

      // Configuration files
      if (
        extension === '.json' ||
        extension === '.yml' ||
        extension === '.yaml' ||
        extension === '.config' ||
        extension === '.env'
      ) {
        return 4;
      }

      // Others
      return 5;
    };

    // Sort files based on priority
    return [...files].sort((a, b) => getFilePriority(a) - getFilePriority(b));
  }

  /**
   * Verify requirements using LLM-powered analysis
   * @param requirements - Requirements to verify
   * @param ruleBasedResults - Results from rule-based verification
   * @param codeChunks - Code chunks to analyze
   * @param repoStructure - Repository structure analysis
   * @param challengeContext - Challenge context for better understanding
   * @param isDeepAnalysisMode - Whether to use deep analysis mode
   * @returns Array of AI-powered verification results
   */
  private async verifyRequirementsWithAI(
    requirements: IStructuredRequirement[],
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>,
    codeChunks: Array<{
      content: string;
      fileCount: number;
      totalSize: number;
      description: string;
    }>,
    repoStructure: IRepositoryStructure,
    challengeContext: IChallengeContext,
    isDeepAnalysisMode: boolean = false
  ): Promise<Array<{
    requirement: IStructuredRequirement;
    satisfied: boolean;
    details: string;
    aiAnalysis?: IAIRequirementVerificationResult;
  }>> {
    // Skip AI verification if no code chunks are available
    if (codeChunks.length === 0) {
      logger.warn('No code chunks available for AI verification');
      return ruleBasedResults.map(result => ({
        ...result,
        aiAnalysis: undefined
      }));
    }

    logger.debug(`Verifying ${requirements.length} requirements with AI (mode: ${isDeepAnalysisMode ? 'deep' : 'standard'})`);

    // Create repository overview
    const repoOverview = this.createRepositoryOverview(repoStructure);

    // Process each requirement with AI
    const aiResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
      aiAnalysis?: IAIRequirementVerificationResult;
    }> = [];

    // Process in batches for more efficient AI usage
    // For deep analysis, use smaller batches for more thorough analysis
    const batchSize = isDeepAnalysisMode ? 2 : 3;
    
    for (let i = 0; i < requirements.length; i += batchSize) {
      const batchRequirements = requirements.slice(i, i + batchSize);

      try {
        // Get rule-based results for these requirements
        const batchRuleBasedResults = batchRequirements.map(req =>
          ruleBasedResults.find(r => r.requirement.id === req.id)
        ).filter(Boolean) as Array<{
          requirement: IStructuredRequirement;
          satisfied: boolean;
          details: string;
        }>;

        // Process the batch with AI
        const batchAIResults = await this.processRequirementBatchWithAI(
          batchRequirements,
          batchRuleBasedResults,
          codeChunks,
          repoOverview,
          challengeContext,
          isDeepAnalysisMode
        );

        // Add results
        aiResults.push(...batchAIResults);

        // Log progress
        logger.debug(`Processed ${i + batchRequirements.length} of ${requirements.length} requirements with AI`, {
          analysisMode: isDeepAnalysisMode ? 'deep' : 'standard'
        });
      } catch (error) {
        logger.error(`Error processing requirement batch with AI`, {
          error: error instanceof Error ? error.message : String(error),
          batchSize: batchRequirements.length,
          deepMode: isDeepAnalysisMode
        });

        // Add rule-based results for the failed batch
        const failedBatchResults = batchRequirements.map(req => {
          const ruleResult = ruleBasedResults.find(r => r.requirement.id === req.id);
          return {
            requirement: req,
            satisfied: ruleResult?.satisfied || false,
            details: ruleResult?.details || 'AI verification failed, using rule-based result',
            aiAnalysis: undefined
          };
        });

        aiResults.push(...failedBatchResults);
      }
    }

    // Fill in the remaining requirements with rule-based results
    const aiResultIds = new Set(aiResults.map(r => r.requirement.id));
    const remainingResults = ruleBasedResults
      .filter(result => !aiResultIds.has(result.requirement.id))
      .map(result => ({
        ...result,
        aiAnalysis: undefined
      }));

    return [...aiResults, ...remainingResults];
  }

  /**
   * Select requirements that need AI verification
   * @param requirements - All requirements
   * @param ruleBasedResults - Results from rule-based verification
   * @returns Array of requirements needing AI verification
   */
  private selectRequirementsForAIVerification(
    requirements: IStructuredRequirement[],
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>
  ): IStructuredRequirement[] {
    // Select requirements based on:
    // 1. Complex requirement types (feature, other, quality)
    // 2. Critical importance
    // 3. Ambiguous rule-based results

    return requirements.filter(req => {
      const ruleResult = ruleBasedResults.find(r => r.requirement.id === req.id);

      if (!ruleResult) return false;

      // Complex requirement types
      const isComplexType = ['feature', 'other', 'quality'].includes(req.type);

      // Critical importance
      const isCritical = req.importance === 'critical';

      // Ambiguous rule-based result
      const isAmbiguous = ruleResult.details.includes('cannot be automatically verified');

      return isComplexType || isCritical || isAmbiguous;
    });
  }

  /**
   * Create a repository overview for AI analysis
   * @param repoStructure - Repository structure analysis
   * @returns Repository overview string
   */
  private createRepositoryOverview(repoStructure: IRepositoryStructure): string {
    // Create a brief overview of the repository structure

    const fileExtensionCounts: Record<string, number> = {};
    repoStructure.fileExtensions.forEach(ext => {
      const count = repoStructure.files.filter(f => f.extension === ext).length;
      if (count > 0) {
        fileExtensionCounts[ext] = count;
      }
    });

    const topDirectories = repoStructure.directories
      .filter(dir => !dir.includes('/'))
      .slice(0, 10);

    const packageSummary = repoStructure.packageFiles
      .map(pkg => {
        const depCount = pkg.dependencies.length + (pkg.devDependencies?.length || 0);
        return `${pkg.path} (${pkg.type}): ${depCount} dependencies`;
      })
      .join('\n');

    return `
Repository Overview:
- Total Files: ${repoStructure.files.length}
- Total Size: ${Math.round(repoStructure.totalSize / 1024)} KB
- Has README: ${repoStructure.hasReadme ? 'Yes' : 'No'}
- File Types: ${Object.entries(fileExtensionCounts)
        .map(([ext, count]) => `${ext} (${count})`)
        .join(', ')}
- Top Directories: ${topDirectories.join(', ')}
- Package Files:
${packageSummary || '  None found'}
    `.trim();
  }

  /**
   * Process a batch of requirements with AI
   * @param requirements - Requirements to verify
   * @param ruleBasedResults - Rule-based verification results
   * @param codeChunks - Code chunks to analyze
   * @param repoOverview - Repository overview
   * @param challengeContext - Challenge context for better understanding
   * @param isDeepAnalysisMode - Whether to use deep analysis mode
   * @returns Results with AI analysis
   */
  private async processRequirementBatchWithAI(
    requirements: IStructuredRequirement[],
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>,
    codeChunks: Array<{
      content: string;
      fileCount: number;
      totalSize: number;
      description: string;
    }>,
    repoOverview: string,
    challengeContext: IChallengeContext,
    isDeepAnalysisMode: boolean = false
  ): Promise<Array<{
    requirement: IStructuredRequirement;
    satisfied: boolean;
    details: string;
    aiAnalysis?: IAIRequirementVerificationResult;
  }>> {
    // Create system prompt for requirements verification
    // Use more detailed prompt in deep analysis mode
    const systemPrompt = isDeepAnalysisMode ? 
      this.createDeepAnalysisSystemPrompt() : 
      this.createRequirementsVerificationSystemPrompt();

    // Create user prompt with repository overview, challenge context, and requirements
    const userPrompt = this.createRequirementsVerificationUserPrompt(
      requirements,
      ruleBasedResults,
      repoOverview,
      challengeContext,
      isDeepAnalysisMode
    );

    // Keep track of chunks analyzed 
    // In deep analysis mode, we analyze more chunks
    const maxChunksToAnalyze = isDeepAnalysisMode ? 
      this.DEEP_ANALYSIS_MAX_CHUNK_COUNT : 
      this.MAX_CHUNK_COUNT;
      
    let chunksAnalyzed = 0;
    const results: IAIRequirementVerificationResult[] = [];

    // Process each code chunk with AI
    for (const chunk of codeChunks) {
      // Skip if we've analyzed enough chunks
      if (chunksAnalyzed >= maxChunksToAnalyze) {
        break;
      }

      try {
        // Create chunk analysis prompt
        // In deep analysis mode, add more context about requirement fulfillment
        const chunkPrompt = isDeepAnalysisMode ? 
          `
Code Chunk ${chunksAnalyzed + 1} (${chunk.description}):

${chunk.content}

Based on this code chunk and what you've analyzed so far, perform a deep analysis of each requirement:
1. Thoroughly examine implementation details
2. Look for edge cases and potential issues
3. Consider both direct and indirect requirement satisfaction
4. Analyze code quality as it relates to requirement fulfillment
5. Provide specific code examples as evidence

For requirements that aren't relevant to this chunk, indicate "No new evidence".
` :
          `
Code Chunk ${chunksAnalyzed + 1} (${chunk.description}):

${chunk.content}

Based on this code chunk and what you've analyzed so far, update your verification of each requirement. For requirements that aren't relevant to this chunk, indicate "No new evidence".
`;

        // Prepare messages for AI
        const messages: ILLMMessage[] = [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ];

        // Add previous results as AI responses if available
        if (results.length > 0) {
          messages.push({
            role: 'assistant',
            content: JSON.stringify(results)
          });
        }

        // Add the chunk prompt
        messages.push({ role: 'user', content: chunkPrompt });

        // Make the API call - use different model parameters based on analysis mode
        const request: ILLMTextRequest = {
          model: isDeepAnalysisMode ? this.DEEP_ANALYSIS_MODEL_NAME : this.MODEL_NAME,
          messages,
          temperature: isDeepAnalysisMode ? this.DEEP_ANALYSIS_TEMPERATURE : this.TEMPERATURE,
          maxTokens: isDeepAnalysisMode ? this.DEEP_ANALYSIS_MAX_TOKENS : this.MAX_TOKENS,
          jsonMode: true
        };

        const response = await this.llmService.generateText(request);

        // Parse and validate the response
        try {
          const chunkResults = JSON.parse(response.text) as IAIRequirementVerificationResult[];

          // Validate the response has the expected structure
          if (!Array.isArray(chunkResults)) {
            throw new Error('Expected array of results');
          }

          // Validate and merge results
          chunkResults.forEach(result => {
            // Check for required fields
            if (
              typeof result.requirementId !== 'string' ||
              typeof result.satisfied !== 'boolean' ||
              typeof result.confidence !== 'number' ||
              !Array.isArray(result.evidenceFound) ||
              typeof result.explanationForUser !== 'string'
            ) {
              throw new Error('Invalid result structure');
            }

            // Find existing result or create new one
            const existingIndex = results.findIndex(r => r.requirementId === result.requirementId);

            if (existingIndex === -1) {
              // Add new result
              results.push(result);
            } else {
              // Merge with existing result
              const existing = results[existingIndex];

              // Update satisfaction if confidence is higher
              if (result.confidence > existing.confidence) {
                existing.satisfied = result.satisfied;
                existing.confidence = result.confidence;
              }

              // Merge evidence
              existing.evidenceFound = [...new Set([...existing.evidenceFound, ...result.evidenceFound])];

              // Update explanation if provided and not "No new evidence"
              if (result.explanationForUser && !result.explanationForUser.includes('No new evidence')) {
                existing.explanationForUser = result.explanationForUser;
              }

              // Keep alternative suggestion if provided
              if (result.alternativeSuggestion) {
                existing.alternativeSuggestion = result.alternativeSuggestion;
              }
            }
          });

          // Increment chunks analyzed
          chunksAnalyzed++;

          logger.debug(`Analyzed chunk ${chunksAnalyzed} for requirements verification (mode: ${isDeepAnalysisMode ? 'deep' : 'standard'})`);
        } catch (parseError) {
          logger.error('Failed to parse AI response for requirements verification', {
            error: parseError instanceof Error ? parseError.message : String(parseError),
            responseText: response.text,
            deepAnalysisMode: isDeepAnalysisMode
          });

          // Continue with next chunk
          chunksAnalyzed++;
        }
      } catch (error) {
        logger.error(`Error analyzing code chunk for requirements verification`, {
          error: error instanceof Error ? error.message : String(error),
          chunkDescription: chunk.description,
          deepAnalysisMode: isDeepAnalysisMode
        });

        // Continue with next chunk
        chunksAnalyzed++;
      }
    }

    // Combine AI results with rule-based results
    return requirements.map(req => {
      const ruleResult = ruleBasedResults.find(r => r.requirement.id === req.id);
      const aiResult = results.find(r => r.requirementId === req.id);

      if (!ruleResult) {
        // This shouldn't happen, but handle it just in case
        return {
          requirement: req,
          satisfied: aiResult?.satisfied || false,
          details: aiResult?.explanationForUser || 'Could not verify requirement',
          aiAnalysis: aiResult
        };
      }

      if (!aiResult) {
        // No AI result, return rule-based result
        return {
          ...ruleResult,
          aiAnalysis: undefined
        };
      }

      // Combine rule-based and AI results
      return {
        requirement: req,
        satisfied: aiResult.satisfied,
        details: aiResult.explanationForUser,
        aiAnalysis: aiResult
      };
    });
  }

  /**
   * Create a more thorough system prompt for deep analysis
   * @returns Enhanced system prompt for deep analysis
   */
  private createDeepAnalysisSystemPrompt(): string {
    return `You are an expert software engineer specializing in technical requirement verification. Your task is to perform a deep, rigorous analysis of code against specified requirements, looking for edge cases and implementation details that might be missed in standard analysis.

For each requirement, you will:
1. Perform a comprehensive code analysis to find all evidence related to the requirement
2. Examine implementation details, edge cases, and potential issues
3. Consider both direct and indirect requirement satisfaction
4. Evaluate code quality as it relates to requirement fulfillment
5. Provide specific code references and examples as evidence
6. Make a final determination with high confidence

Expected output format is a JSON array of objects with this structure:
[
  {
    "requirementId": string,  // ID of the requirement being verified
    "satisfied": boolean,    // Whether the requirement is satisfied
    "confidence": number,    // 0-100 confidence score
    "evidenceFound": string[],  // Array of specific evidence from the code with line references
    "explanationForUser": string,  // Thorough explanation of findings
    "alternativeSuggestion": string  // Detailed suggestion if requirement is not met
  }
]

Guidelines for verification:
- Be extremely thorough in your code examination
- For file requirements, check not only existence but proper implementation
- For package requirements, verify correct usage beyond mere inclusion
- For feature requirements, validate completeness of implementation
- For quality requirements, perform detailed code quality assessment

Confidence levels should be assigned as follows:
- 95-100: Conclusive evidence with extensive verification
- 85-94: Strong evidence with minor uncertainties
- 70-84: Solid evidence but some gaps in verification
- 50-69: Mixed evidence with significant uncertainties
- 30-49: Limited evidence with many gaps
- 0-29: Insufficient evidence

Your response MUST be valid JSON that can be parsed directly. Put extra effort into finding evidence and providing specific code references.`;
  }

  /**
   * Create system prompt for requirements verification
   * @returns System prompt
   */
  private createRequirementsVerificationSystemPrompt(): string {
    return `You are a specialized AI for verifying software requirements compliance in GitHub repositories. Your task is to analyze code and determine if it meets specified requirements.

For each requirement, you will:
1. Examine the code to find evidence that the requirement is satisfied
2. Make a determination (satisfied or not) with a confidence level
3. Provide specific evidence found in the code
4. Give a clear explanation for the user

Expected output format is a JSON array of objects with this structure:
[
  {
    "requirementId": string,  // ID of the requirement being verified
    "satisfied": boolean,    // Whether the requirement is satisfied
    "confidence": number,    // 0-100 confidence score
    "evidenceFound": string[],  // Array of specific evidence from the code
    "explanationForUser": string,  // Clear explanation for the user
    "alternativeSuggestion": string  // Optional suggestion if requirement is not met
  }
]

Guidelines for verification:
- Be thorough but fair in your assessment
- For file requirements, check if the specified files exist
- For package requirements, check dependencies or import statements
- For feature requirements, look for implementation evidence
- For structure requirements, analyze the code organization
- For quality requirements, evaluate based on code standards

When evaluating confidence:
- 90-100: Conclusive evidence found
- 70-89: Strong evidence but some uncertainty
- 50-69: Mixed evidence
- 30-49: Limited evidence
- 0-29: No clear evidence

Your response MUST be valid JSON that can be parsed directly.`;
  }

  /**
   * Create user prompt for requirements verification
   * @param requirements - Requirements to verify
   * @param ruleBasedResults - Rule-based verification results
   * @param repoOverview - Repository overview
   * @param challengeContext - Challenge context for better understanding
   * @param isDeepAnalysisMode - Whether to use deep analysis mode
   * @returns User prompt
   */
  private createRequirementsVerificationUserPrompt(
    requirements: IStructuredRequirement[],
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>,
    repoOverview: string,
    challengeContext: IChallengeContext,
    isDeepAnalysisMode: boolean = false
  ): string {
    // Format requirements for the prompt
    const formattedRequirements = requirements.map((req, index) => {
      const ruleResult = ruleBasedResults.find(r => r.requirement.id === req.id);

      return `Requirement ${index + 1} (ID: ${req.id}):
- Name: ${req.name}
- Description: ${req.description}
- Type: ${req.type}
- Importance: ${req.importance}
${req.filePath ? `- Expected File: ${req.filePath}` : ''}
${req.filePattern ? `- Expected File Pattern: ${req.filePattern}` : ''}
${req.extensions ? `- Expected Extensions: ${req.extensions.join(', ')}` : ''}
${req.packageName ? `- Expected Package: ${req.packageName}` : ''}
${req.packageType ? `- Package Type: ${req.packageType}` : ''}
${ruleResult ? `- Rule-based Result: ${ruleResult.satisfied ? 'SATISFIED' : 'NOT SATISFIED'}
- Rule-based Details: ${ruleResult.details}` : ''}`;
    }).join('\n\n');

    // Format challenge context
    const challengeInfo = `
Challenge Information:
- Title: ${challengeContext.title}
- Description: ${challengeContext.description.substring(0, 500)}${challengeContext.description.length > 500 ? '...' : ''}
${challengeContext.category ? `- Categories: ${challengeContext.category.join(', ')}` : ''}
${challengeContext.difficulty ? `- Difficulty Level: ${challengeContext.difficulty}` : ''}
${challengeContext.tags?.length ? `- Tags: ${challengeContext.tags.join(', ')}` : ''}

Original Challenge Requirements:
${challengeContext.requirements.map(req => `- ${req}`).join('\n')}
`;

    return `
${challengeInfo}

${repoOverview}

I need you to verify the following structured requirements against the code in this repository:

${formattedRequirements}

I'll provide code chunks incrementally. For each chunk, analyze the code and update your verification.
Your response should be a JSON array with verification results for each requirement.
`;
  }

  /**
   * Blend rule-based and AI verification results
   * @param ruleBasedResults - Rule-based verification results
   * @param aiResults - AI verification results
   * @param isDeepAnalysisMode - Whether to use deep analysis mode
   * @returns Blended verification results
   */
  private blendVerificationResults(
    ruleBasedResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>,
    aiResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
      aiAnalysis?: IAIRequirementVerificationResult;
    }>,
    isDeepAnalysisMode: boolean = false
  ): Array<{
    requirement: IStructuredRequirement;
    satisfied: boolean;
    details: string;
  }> {
    // For each requirement, determine the final result
    return ruleBasedResults.map(ruleResult => {
      // Find corresponding AI result
      const aiResult = aiResults.find(r => r.requirement.id === ruleResult.requirement.id);

      // If no AI result or no AI analysis, use rule-based result
      if (!aiResult || !aiResult.aiAnalysis) {
        return ruleResult;
      }

      // In deep analysis mode, prefer AI results more strongly
      if (isDeepAnalysisMode) {
        // For deep analysis, we prefer AI results as long as confidence is reasonable
        const preferAI = aiResult.aiAnalysis.confidence >= 60; // Lower threshold in deep mode
        
        if (preferAI) {
          return {
            requirement: ruleResult.requirement,
            satisfied: aiResult.satisfied,
            details: `[Deep Analysis] ${aiResult.details}`
          };
        } else {
          // Even with low confidence, blend the AI insights with rule-based result
          return {
            requirement: ruleResult.requirement,
            satisfied: ruleResult.satisfied,
            details: `[Rule-based with AI insights] ${ruleResult.details}. AI analysis: ${aiResult.details}`
          };
        }
      } else {
        // Standard mode - use existing logic
        const useAIResult = this.shouldPreferAIResult(ruleResult, aiResult);
        
        if (useAIResult) {
          return {
            requirement: ruleResult.requirement,
            satisfied: aiResult.satisfied,
            details: aiResult.details
          };
        } else {
          return ruleResult;
        }
      }
    });
  }

  /**
   * Determine if AI result should be preferred over rule-based result
   * @param ruleResult - Rule-based verification result
   * @param aiResult - AI verification result
   * @returns Boolean indicating if AI result should be preferred
   */
  private shouldPreferAIResult(
    ruleResult: {
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    },
    aiResult: {
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
      aiAnalysis?: IAIRequirementVerificationResult;
    }
  ): boolean {
    if (!aiResult.aiAnalysis) {
      return false;
    }

    // Always prefer AI for complex requirement types
    const complexTypes = ['feature', 'other', 'quality'];
    if (complexTypes.includes(ruleResult.requirement.type)) {
      return true;
    }

    // Prefer AI if rule-based result is ambiguous
    if (ruleResult.details.includes('cannot be automatically verified')) {
      return true;
    }

    // Prefer AI if confidence is high
    if (aiResult.aiAnalysis.confidence >= 80) {
      return true;
    }

    // Prefer AI for critical requirements
    if (ruleResult.requirement.importance === 'critical' && aiResult.aiAnalysis.confidence >= 70) {
      return true;
    }

    // In case of disagreement, prefer rule-based for basic requirements
    if (ruleResult.satisfied !== aiResult.satisfied) {
      const basicTypes = ['file', 'package', 'structure'];
      if (basicTypes.includes(ruleResult.requirement.type)) {
        return false;
      }
    }

    // Default to AI result for any other case
    return true;
  }

  /**
   * Create a standardized error result
   * @param message - Error message
   * @returns Standardized error result
   */
  private createErrorResult(message: string): IRequirementsComplianceResult {
    return {
      score: 30,
      feedback: message,
      metadata: {
        requirementsSatisfied: 0,
        totalRequirements: 0,
        missingRequirements: [message],
        formatErrors: ['Unable to validate format'],
        repositoryStructure: {
          hasRequiredFiles: false,
          missingFiles: ['Unable to validate'],
          hasReadme: false,
          hasProperStructure: false
        }
      },
      evaluatedAt: new Date()
    };
  }

  /**
   * Extract GitHub repository information from URL with enterprise-level security
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

  /**
   * Extract structured requirements from challenge context
   * @param challengeContext - The challenge context with requirements data
   * @returns List of structured requirements
   */
  private extractStructuredRequirements(challengeContext: IChallengeContext): IStructuredRequirement[] {
    // Initialize requirements array
    const requirements: IStructuredRequirement[] = [];

    // Log that we're starting requirement extraction
    logger.debug(`Extracting requirements for challenge: ${challengeContext.title}`, {
      challengeId: challengeContext.challengeId
    });

    // Check if challenge context has requirements array
    if (challengeContext.requirements && challengeContext.requirements.length > 0) {
      logger.debug(`Challenge has requirements (${challengeContext.requirements.length})`, {
        challengeId: challengeContext.challengeId
      });

      // First, parse any structured requirements (if they exist)
      // We assume requirements might be simple strings or could be serialized JSON objects
      challengeContext.requirements.forEach((req, index) => {
        try {
          // Try to parse as JSON if it looks like an object
          if (req.trim().startsWith('{') && req.trim().endsWith('}')) {
            const parsedReq = JSON.parse(req);
            
            // Create structured requirement with parsed data
            const requirement: IStructuredRequirement = {
              id: parsedReq.id || `req_${index}`,
              name: parsedReq.name || `Requirement ${index + 1}`,
              description: parsedReq.description || req,
              type: this.validateRequirementType(parsedReq.type),
              importance: this.validateRequirementImportance(parsedReq.importance)
            };

            // Add optional properties if they exist
            if (parsedReq.filePath) requirement.filePath = parsedReq.filePath;
            if (parsedReq.filePattern) requirement.filePattern = parsedReq.filePattern;
            if (parsedReq.extensions) requirement.extensions = parsedReq.extensions;
            if (parsedReq.packageName) requirement.packageName = parsedReq.packageName;
            if (parsedReq.packageType) requirement.packageType = parsedReq.packageType;

            requirements.push(requirement);
            
            logger.debug(`Added structured JSON requirement: ${requirement.name}`, {
              requirementId: requirement.id,
              importance: requirement.importance,
              type: requirement.type
            });
          } else {
            // If it's a simple string, create a basic requirement
            this.addRequirementFromText(req, `req_${index}`, requirements);
            logger.debug(`Added requirement from text: ${req.substring(0, 50)}...`, {
              requirementIndex: index
            });
          }
        } catch (error) {
          // If parsing fails, treat as plain text
          this.addRequirementFromText(req, `req_${index}`, requirements);
          logger.debug(`Added requirement from text (parse failed): ${req.substring(0, 50)}...`, {
            requirementIndex: index,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      });
    } else {
      logger.warn(`No requirements found in challenge context`, {
        challengeId: challengeContext.challengeId
      });
    }

    // Also analyze the challenge description for additional implicit requirements
    this.analyzeDescriptionForAdditionalRequirements(challengeContext.description, requirements);

    // If we still have no requirements, add some basic defaults
    if (requirements.length === 0) {
      logger.warn(`No requirements extracted from challenge. Using basic defaults.`, {
        challengeId: challengeContext.challengeId
      });

      // Add some basic requirements as a fallback
      requirements.push({
        id: 'req_code',
        name: 'Code Implementation',
        description: 'Project must contain code files implementing the solution',
        type: 'other',
        importance: 'critical'
      });

      requirements.push({
        id: 'req_docs',
        name: 'Documentation',
        description: 'Project should have basic documentation',
        type: 'file',
        importance: 'important',
        filePath: 'README.md'
      });
    }

    // Look for specific technology requirements from the description
    const techRequirements = this.extractTechnologyRequirements(challengeContext.description);

    // Add technology requirements if found
    techRequirements.forEach((tech, index) => {
      // Check if this technology requirement already exists
      const existingTechReq = requirements.find(req =>
        req.type === 'package' &&
        req.packageName &&
        req.packageName.toLowerCase() === tech.toLowerCase()
      );

      if (!existingTechReq) {
        requirements.push({
          id: `req_tech_${index}`,
          name: `${tech} Usage`,
          description: `Project must use ${tech}`,
          type: 'package',
          importance: 'important',
          packageName: tech.toLowerCase(),
          packageType: this.determinePackageType(tech)
        });

        logger.debug(`Added technology requirement for: ${tech}`, {
          technologyName: tech,
          packageType: this.determinePackageType(tech)
        });
      }
    });

    // Final logging of extracted requirements
    logger.info(`Extracted ${requirements.length} requirements for challenge`, {
      challengeId: challengeContext.challengeId,
      requirementCount: requirements.length,
      criticalCount: requirements.filter(r => r.importance === 'critical').length
    });

    return requirements;
  }

  /**
   * Validate requirement type to ensure it's one of the allowed values
   * @param type - The type to validate
   * @returns Valid requirement type
   */
  private validateRequirementType(type: any): IStructuredRequirement['type'] {
    const validTypes: IStructuredRequirement['type'][] = ['file', 'package', 'structure', 'feature', 'quality', 'other'];
    
    if (typeof type === 'string' && validTypes.includes(type as IStructuredRequirement['type'])) {
      return type as IStructuredRequirement['type'];
    }
    
    return 'other';
  }

  /**
   * Validate requirement importance to ensure it's one of the allowed values
   * @param importance - The importance to validate
   * @returns Valid requirement importance
   */
  private validateRequirementImportance(importance: any): IStructuredRequirement['importance'] {
    const validImportance: IStructuredRequirement['importance'][] = ['critical', 'important', 'optional'];
    
    if (typeof importance === 'string' && validImportance.includes(importance as IStructuredRequirement['importance'])) {
      return importance as IStructuredRequirement['importance'];
    }
    
    return 'important';
  }

  /**
   * Split description into logical sections for better analysis
   * @param description - The challenge description
   * @returns Array of description sections
   */
  private splitDescriptionIntoSections(description: string): string[] {
    // Split by common section markers
    const sections: string[] = [];

    // Look for headers like "# Requirements" or "## Technical Requirements"
    const headerRegex = /(?:^|\n)(?:#{1,6})\s+(.+?)(?:\n|$)/g;
    const headerMatches = [...description.matchAll(headerRegex)];

    if (headerMatches.length > 0) {
      // Use headers to split sections
      let lastIndex = 0;

      for (let i = 0; i < headerMatches.length; i++) {
        const match = headerMatches[i];
        const nextMatch = headerMatches[i + 1] || null;

        if (match.index !== undefined) {
          // If this isn't the first header, add previous section
          if (match.index > lastIndex) {
            sections.push(description.substring(lastIndex, match.index).trim());
          }

          // Calculate end of this section
          const endIndex = nextMatch && nextMatch.index !== undefined
            ? nextMatch.index
            : description.length;

          // Add header to section content
          const sectionContent = description.substring(match.index, endIndex).trim();
          sections.push(sectionContent);

          lastIndex = endIndex;
        }
      }

      // Add final section if needed
      if (lastIndex < description.length) {
        sections.push(description.substring(lastIndex).trim());
      }
    } else {
      // Try splitting by blank lines if no headers
      const blankLineRegex = /\n\s*\n/;
      sections.push(...description.split(blankLineRegex).filter(s => s.trim().length > 0));
    }

    // If still no reasonable sections, use the whole description
    if (sections.length === 0) {
      sections.push(description);
    }

    return sections;
  }

  /**
   * Analyze a description section for possible requirements
   * @param section - Section of the challenge description
   * @param requirements - Requirements array to update
   */
  private analyzeDescriptionSection(section: string, requirements: IStructuredRequirement[]): void {
    const sectionLower = section.toLowerCase();

    // Check if this section looks like requirements
    const isRequirementsSection =
      sectionLower.includes('requirements') ||
      sectionLower.includes('must have') ||
      sectionLower.includes('must include') ||
      sectionLower.includes('should have') ||
      sectionLower.includes('should include') ||
      sectionLower.includes('deliverables') ||
      sectionLower.includes('specifications');

    if (isRequirementsSection) {
      // Extract requirements from bullet points or numbered lists
      const listItemRegex = /(?:^|\n)[\s-]*(?:\d+\.|\*|\-|\+|\•)\s+(.+?)(?:\n|$)/g;
      const listMatches = [...section.matchAll(listItemRegex)];

      if (listMatches.length > 0) {
        listMatches.forEach((match, index) => {
          if (match[1]) {
            const itemText = match[1].trim();
            this.addRequirementFromText(itemText, `list_req_${index}`, requirements);
          }
        });
      } else {
        // If no list items, look for sentences that might describe requirements
        const sentences = section.split(/(?<=[.!?])\s+/);
        sentences.forEach((sentence, index) => {
          if (this.sentenceContainsRequirement(sentence)) {
            this.addRequirementFromText(sentence, `sent_req_${index}`, requirements);
          }
        });
      }
    }

    // Always check for code quality mentions
    if (
      sectionLower.includes('code quality') ||
      sectionLower.includes('clean code') ||
      sectionLower.includes('best practices') ||
      sectionLower.includes('code standards')
    ) {
      // Add code quality as an explicit requirement if not already present
      const hasQualityReq = requirements.some(req => 
        req.type === 'quality' || 
        (req.name && req.name.toLowerCase().includes('quality'))
      );
      
      if (!hasQualityReq) {
        requirements.push({
          id: 'req_code_quality',
          name: 'Code Quality',
          description: 'Project must demonstrate good code quality and best practices',
          type: 'quality',
          importance: 'important'
        });
      }
    }

    // Check for README/documentation requirements
    if (
      sectionLower.includes('readme') ||
      sectionLower.includes('documentation') ||
      sectionLower.includes('document your')
    ) {
      const existingReadmeReq = requirements.some(req =>
        req.type === 'file' &&
        req.filePath &&
        req.filePath.toLowerCase().includes('readme')
      );

      if (!existingReadmeReq) {
        requirements.push({
          id: 'req_readme',
          name: 'README Documentation',
          description: 'Project must have a README file with appropriate documentation',
          type: 'file',
          importance: 'important',
          filePath: 'README.md'
        });
      }
    }
  }

  /**
   * Add a requirement based on text analysis
   * @param text - The text that might contain a requirement
   * @param idPrefix - Prefix for the requirement ID
   * @param requirements - Requirements array to update
   */
  private addRequirementFromText(text: string, idPrefix: string, requirements: IStructuredRequirement[]): void {
    const lowerText = text.toLowerCase();

    // Determine requirement importance
    const isCritical =
      lowerText.includes('must') ||
      lowerText.includes('required') ||
      lowerText.includes('essential') ||
      lowerText.includes('critical');

    const importance: IStructuredRequirement['importance'] = isCritical ? 'critical' : 'important';

    // Check for file requirements
    if (
      lowerText.includes('file') ||
      lowerText.includes('.js') ||
      lowerText.includes('.py') ||
      lowerText.includes('.html') ||
      lowerText.includes('.css') ||
      lowerText.includes('.json')
    ) {
      // Try to extract a specific filename or pattern
      const fileNameMatch = text.match(/['"a-zA-Z0-9_-]+\.[a-zA-Z0-9]+/);
      if (fileNameMatch) {
        requirements.push({
          id: `${idPrefix}_file`,
          name: `Required File: ${fileNameMatch[0]}`,
          description: text,
          type: 'file',
          importance,
          filePath: fileNameMatch[0]
        });
        return;
      }

      // Look for file extension requirements
      const extensionMatches = [...text.matchAll(/\.([a-zA-Z0-9]+)/g)];
      if (extensionMatches.length > 0) {
        const extensions = extensionMatches.map(match => match[0]);
        requirements.push({
          id: `${idPrefix}_ext`,
          name: `Required File Extensions: ${extensions.join(', ')}`,
          description: text,
          type: 'file',
          importance,
          extensions
        });
        return;
      }
    }

    // Check for technology-specific requirements
    for (const tech of commonTechnologies) {
      if (lowerText.includes(tech.toLowerCase())) {
        requirements.push({
          id: `${idPrefix}_tech_${tech}`,
          name: `${tech} Usage`,
          description: text,
          type: 'package',
          importance,
          packageName: tech.toLowerCase(),
          packageType: this.determinePackageType(tech)
        });
        return;
      }
    }

    // Default to a general requirement
    requirements.push({
      id: idPrefix,
      name: text.length > 50 ? `${text.substring(0, 47)}...` : text,
      description: text,
      type: 'other',
      importance
    });
  }

  /**
   * Check if a sentence likely contains a requirement
   * @param sentence - The sentence to analyze
   * @returns Whether the sentence likely describes a requirement
   */
  private sentenceContainsRequirement(sentence: string): boolean {
    const lowerSentence = sentence.toLowerCase();

    return (
      lowerSentence.includes('must') ||
      lowerSentence.includes('should') ||
      lowerSentence.includes('need to') ||
      lowerSentence.includes('required') ||
      lowerSentence.includes('implement') ||
      lowerSentence.includes('create') ||
      lowerSentence.includes('develop') ||
      lowerSentence.includes('use ') ||
      lowerSentence.includes('using ') ||
      lowerSentence.includes('include ')
    );
  }

  /**
   * Analyze description for additional requirements beyond what's structured
   * @param description - Challenge description
   * @param requirements - Requirements array to update
   */
  private analyzeDescriptionForAdditionalRequirements(description: string, requirements: IStructuredRequirement[]): void {
    // Look for README/documentation requirements if not already included
    const hasReadmeRequirement = requirements.some(req =>
      req.type === 'file' &&
      req.filePath &&
      req.filePath.toLowerCase().includes('readme')
    );

    if (!hasReadmeRequirement &&
      (description.toLowerCase().includes('readme') ||
        description.toLowerCase().includes('documentation'))) {
      requirements.push({
        id: 'req_readme',
        name: 'README Documentation',
        description: 'Project must have a README file with appropriate documentation',
        type: 'file',
        importance: 'important',
        filePath: 'README.md'
      });
    }

    // Look for specific code quality requirements
    const hasCodeQualityRequirement = requirements.some(req =>
      req.type === 'quality' ||
      (req.name && req.name.toLowerCase().includes('quality'))
    );

    if (!hasCodeQualityRequirement &&
      (description.toLowerCase().includes('code quality') ||
        description.toLowerCase().includes('clean code') ||
        description.toLowerCase().includes('best practices'))) {
      requirements.push({
        id: 'req_code_quality',
        name: 'Code Quality',
        description: 'Project must demonstrate good code quality and best practices',
        type: 'quality',
        importance: 'important'
      });
    }
    
    // Look for sections that could be requirements
    const sections = this.splitDescriptionIntoSections(description);
    
    // Analyze each section of the description for potential requirements
    for (const section of sections) {
      this.analyzeDescriptionSection(section, requirements);
    }
  }

  /**
   * Extract technology requirements from challenge description
   * @param description - Challenge description
   * @returns List of technology names
   */
  private extractTechnologyRequirements(description: string): string[] {
    const technologies: string[] = [];

    for (const tech of commonTechnologies) {
      // Check for exact tech names surrounded by spaces, punctuation, or line boundaries
      const regex = new RegExp(`(^|\\s|[.,;:!?])${tech}(\\s|[.,;:!?]|$)`, 'i');
      if (regex.test(description)) {
        technologies.push(tech);
      }
    }

    return technologies;
  }

  /**
   * Determine package type based on technology name
   * @param technology - Technology name
   * @returns Package type
   */
  private determinePackageType(technology: string): 'npm' | 'python' | 'ruby' | 'other' {
    const tech = technology.toLowerCase();

    // JavaScript/Node.js ecosystem
    if (['react', 'angular', 'vue', 'node.js', 'express', 'typescript', 'javascript'].includes(tech)) {
      return 'npm';
    }

    // Python ecosystem
    if (['python', 'django', 'flask'].includes(tech)) {
      return 'python';
    }

    // Ruby ecosystem
    if (['ruby', 'rails'].includes(tech)) {
      return 'ruby';
    }

    // Default
    return 'other';
  }

  /**
   * Verify requirements against repository
   * @param repoInfo - Repository information
   * @param structure - Repository structure analysis
   * @param requirements - Challenge requirements
   * @returns Array of requirement verification results
   */
  private async verifyRequirements(
    repoInfo: { owner: string; repo: string; url: string },
    structure: IRepositoryStructure,
    requirements: IStructuredRequirement[]
  ): Promise<Array<{
    requirement: IStructuredRequirement;
    satisfied: boolean;
    details: string;
  }>> {
    const results: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }> = [];

    // Process each requirement
    for (const requirement of requirements) {
      let satisfied = false;
      let details = '';

      // Check different requirement types
      switch (requirement.type) {
        case 'file':
          // Check if file exists
          if (requirement.filePath) {
            const fileExists = structure.files.some(file =>
              file.path.toLowerCase() === requirement.filePath?.toLowerCase()
            );

            satisfied = fileExists;
            details = fileExists
              ? `File ${requirement.filePath} exists`
              : `File ${requirement.filePath} not found`;
          } else if (requirement.filePattern) {
            // Check for file pattern
            const regex = new RegExp(requirement.filePattern, 'i');
            const matchingFiles = structure.files.filter(file => regex.test(file.path));

            satisfied = matchingFiles.length > 0;
            details = satisfied
              ? `Found ${matchingFiles.length} files matching pattern ${requirement.filePattern}`
              : `No files matching pattern ${requirement.filePattern}`;
          } else if (requirement.extensions && requirement.extensions.length > 0) {
            // Check for file extensions
            const hasExtensions = requirement.extensions.some(ext =>
              structure.fileExtensions.has(ext.startsWith('.') ? ext.toLowerCase() : `.${ext.toLowerCase()}`)
            );

            satisfied = hasExtensions;
            details = satisfied
              ? `Found files with required extensions: ${requirement.extensions.join(', ')}`
              : `No files with required extensions: ${requirement.extensions.join(', ')}`;
          }
          break;

        case 'package':
          // Check if package is used
          if (requirement.packageName) {
            const packageFound = structure.packageFiles.some(pkg =>
              pkg.dependencies.some(dep =>
                dep.toLowerCase().includes(requirement.packageName!.toLowerCase())
              ) || (pkg.devDependencies && pkg.devDependencies.some(dep =>
                dep.toLowerCase().includes(requirement.packageName!.toLowerCase())
              ))
            );

            satisfied = packageFound;
            details = packageFound
              ? `Package ${requirement.packageName} is used in the project`
              : `Package ${requirement.packageName} not found in dependencies`;
          }
          break;

        case 'structure':
          // Generic structure requirement (README, etc.)
          if (requirement.name.toLowerCase().includes('readme') ||
            requirement.description.toLowerCase().includes('readme')) {
            satisfied = structure.hasReadme;
            details = satisfied
              ? 'Repository has a README file'
              : 'Repository is missing a README file';
          } else {
            satisfied = structure.hasProperStructure;
            details = satisfied
              ? 'Repository has proper structure'
              : 'Repository lacks proper structure';
          }
          break;

        case 'feature':
        case 'quality':
        case 'other':
        default:
          // For requirements we can't automatically verify, use basic heuristics
          // In a real implementation, this might use AI to analyze code more deeply

          // If README exists, check if it mentions the requirement
          if (structure.readmeContent && requirement.name) {
            const nameInReadme = structure.readmeContent.toLowerCase()
              .includes(requirement.name.toLowerCase());
            const descInReadme = requirement.description && structure.readmeContent.toLowerCase()
              .includes(requirement.description.toLowerCase());

            if (nameInReadme || descInReadme) {
              satisfied = true;
              details = `Requirement "${requirement.name}" mentioned in README`;
            } else {
              satisfied = false;
              details = `No mention of "${requirement.name}" in README`;
            }
          } else {
            // Default for unverifiable requirements
            satisfied = true; // Assume satisfied if can't verify
            details = 'Requirement cannot be automatically verified';
          }
          break;
      }

      // Add to results
      results.push({
        requirement,
        satisfied,
        details
      });
    }

    return results;
  }

  /**
   * Calculate scores and generate feedback
   * @param requirementResults - Requirement verification results
   * @param structure - Repository structure analysis
   * @param description - Solution description
   * @param challengeContext - Challenge context for better feedback
   * @param isDeepAnalysisMode - Whether to use deep analysis mode
   * @returns Score, feedback, and metadata
   */
  private calculateScoresAndFeedback(
    requirementResults: Array<{
      requirement: IStructuredRequirement;
      satisfied: boolean;
      details: string;
    }>,
    structure: IRepositoryStructure,
    description: string,
    challengeContext: IChallengeContext,
    isDeepAnalysisMode: boolean = false
  ): [number, string, IRequirementsComplianceResult['metadata']] {
    // Count satisfied requirements
    const totalRequirements = requirementResults.length;
    const satisfiedRequirements = requirementResults.filter(r => r.satisfied).length;

    // Calculate basic score percentage
    let baseScore = (satisfiedRequirements / totalRequirements) * 100;

    // Count critical requirements
    const criticalRequirements = requirementResults.filter(r =>
      r.requirement.importance === 'critical'
    );

    const satisfiedCritical = criticalRequirements.filter(r => r.satisfied).length;

    // Significant penalty for missing critical requirements
    if (criticalRequirements.length > 0 && satisfiedCritical < criticalRequirements.length) {
      // In deep analysis mode, we apply a stronger penalty for missing critical requirements
      const criticalPenaltyFactor = isDeepAnalysisMode ? 70 : 50;
      const criticalPenalty =
        ((criticalRequirements.length - satisfiedCritical) / criticalRequirements.length) * criticalPenaltyFactor;
      baseScore = Math.max(0, baseScore - criticalPenalty);
    }

    // Structure penalties - more strict in deep analysis mode
    const structurePenalty = !structure.hasProperStructure ? (isDeepAnalysisMode ? 15 : 10) : 0;
    const readmePenalty = !structure.hasReadme ? (isDeepAnalysisMode ? 15 : 10) : 0;

    // Description penalties
    const formatErrors: string[] = [];
    if (description.length < 50) {
      formatErrors.push('Solution description is too brief (less than 50 characters)');
    }

    // More detailed format checks in deep analysis mode
    if (isDeepAnalysisMode) {
      if (description.length < 200 && challengeContext.difficulty !== ChallengeDifficulty.BEGINNER) {
        formatErrors.push('Solution description lacks sufficient detail for non-beginner challenge');
      }
      if (!description.includes(challengeContext.title)) {
        formatErrors.push('Solution description does not reference the challenge title');
      }
    }

    const formatPenalty = formatErrors.length * (isDeepAnalysisMode ? 7 : 5);

    // Calculate final score
    const finalScore = Math.max(0, Math.min(100,
      baseScore - structurePenalty - readmePenalty - formatPenalty
    ));

    // Generate missing requirements list
    const missingRequirements = requirementResults
      .filter(r => !r.satisfied)
      .map(r => `${r.requirement.name} - ${r.details}`);

    // Generate appropriate feedback with challenge context awareness
    let feedback = '';
    
    // More detailed feedback in deep analysis mode
    if (isDeepAnalysisMode) {
      if (finalScore > 85) {
        feedback = `[Deep Analysis] The solution for "${challengeContext.title}" comprehensively meets requirements with strong implementation quality.`;
      } else if (finalScore > 70) {
        feedback = `[Deep Analysis] The solution for "${challengeContext.title}" meets most requirements but has areas for improvement in implementation details.`;
      } else if (finalScore > 50) {
        feedback = `[Deep Analysis] The solution for "${challengeContext.title}" partially meets requirements but has significant implementation gaps.`;
      } else {
        feedback = `[Deep Analysis] The solution for "${challengeContext.title}" fails to properly implement several key requirements.`;
      }
    } else {
      // Standard mode feedback
      if (finalScore > 80) {
        feedback = `The solution for "${challengeContext.title}" meets most requirements with only minor issues.`;
      } else if (finalScore > 50) {
        feedback = `The solution for "${challengeContext.title}" meets basic requirements but has significant gaps.`;
      } else {
        feedback = `The solution for "${challengeContext.title}" fails to meet several key requirements.`;
      }
    }

    // Add details about missing requirements
    if (missingRequirements.length > 0) {
      feedback += ' Missing requirements: ' + missingRequirements.join('; ') + '.';
    }

    // Add details about repository structure
    if (!structure.hasProperStructure) {
      feedback += ' Repository structure does not follow best practices.';
    }

    // Add details about format issues
    if (formatErrors.length > 0) {
      feedback += ' Format issues: ' + formatErrors.join('; ') + '.';
    }

    // Add general information on challenge difficulty if available
    if (challengeContext.difficulty) {
      feedback += ` This was a ${challengeContext.difficulty.toLowerCase()} level challenge.`;
    }

    // Prepare metadata with enhanced information
    const metadata = {
      requirementsSatisfied: satisfiedRequirements,
      totalRequirements,
      missingRequirements,
      formatErrors,
      repositoryStructure: {
        hasRequiredFiles: structure.missingFiles.length === 0,
        missingFiles: structure.missingFiles,
        hasReadme: structure.hasReadme,
        hasProperStructure: structure.hasProperStructure
      }
    } as IRequirementsComplianceResult['metadata'];

    // Add enhanced metadata using type assertion
    const enhancedMetadata = {
      ...metadata,
      // Custom properties for enhanced analysis
      challengeInfo: {
        id: challengeContext.challengeId,
        title: challengeContext.title,
        difficulty: challengeContext.difficulty,
        categories: challengeContext.category
      },
      analysisMode: isDeepAnalysisMode ? 'deep' : 'standard',
      confidence: isDeepAnalysisMode ? 'high' : 'standard',
      criticalRequirementsMet: satisfiedCritical,
      totalCriticalRequirements: criticalRequirements.length
    };

    return [
      Math.round(finalScore), // Round to whole number
      feedback,
      enhancedMetadata
    ];
  }

  /**
   * Override determineDecision to handle enhanced decision logic
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or request review
   */
  public determineDecision(result: IRequirementsComplianceResult): EvaluationDecision {
    // We'll use the requirementsSatisfied and totalRequirements that exist in the metadata
    const { requirementsSatisfied, totalRequirements } = result.metadata;

    // First check the overall requirements ratio - we require at least 70% of requirements to be met
    const requirementsRatio = requirementsSatisfied / totalRequirements;

    // Fail if less than 70% of requirements are met
    if (requirementsRatio < 0.7) {
      logger.info(`Failing submission due to insufficient requirements satisfaction`, {
        requirementsSatisfied,
        totalRequirements,
        ratio: requirementsRatio.toFixed(2)
      });
      return EvaluationDecision.FAIL;
    }

    // Review for borderline cases (70-85% requirement satisfaction)
    if (requirementsRatio < 0.85) {
      return EvaluationDecision.REVIEW;
    }

    // Pass if most requirements are met (>= 85%)
    return EvaluationDecision.PASS;
  }
}

// Export singleton instance
export const requirementsComplianceAgent = RequirementsComplianceAgent.getInstance(); 