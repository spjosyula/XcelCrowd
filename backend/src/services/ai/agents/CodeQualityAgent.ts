import { AIAgentBase } from '../AIAgentBase';
import {
  ICodeQualityResult,
  ISolution,
  EvaluationDecision,
  IFileInfo,
  IFileMetrics,
  ICodeIssue,
  IVulnerabilityResult,
  IRepositoryAnalysis,
  IVulnerabilityPattern,
  ICachedRepositoryAnalysis
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { setTimeout } from 'timers/promises';
import * as crypto from 'crypto';
import { GitHubService} from '../../../services/github.service';
import { ProgrammingLanguage, FILE_EXTENSION_TO_LANGUAGE } from '../../../constants/common.tech.things';
import { LLMService } from '../../llm/LLMService';
import { ILLMTextRequest, ILLMMessage } from '../../llm/interfaces/ILLMRequest';
import { ILLMService } from '../../llm/interfaces/ILLMService';

// Cache TTL - 30 minutes
const CACHE_TTL = 30 * 60 * 1000;

/**
 * Code Quality Agent
 * Evaluates code quality of GitHub repository submissions
 */
export class CodeQualityAgent extends AIAgentBase<ICodeQualityResult> {
  private static instance: CodeQualityAgent;
  public name = 'CodeQualityAgent';
  public description = 'Analyzes code quality metrics for GitHub submissions';

  // Cache for repository analysis results
  private static repositoryCache: Map<string, ICachedRepositoryAnalysis> = new Map();

  // LLM service for advanced code analysis
  private readonly llmService: ILLMService;

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    super();
    this.llmService = LLMService.getInstance();
  }

  /**
   * Get the singleton instance
   * @returns The CodeQualityAgent instance
   */
  public static getInstance(): CodeQualityAgent {
    if (!CodeQualityAgent.instance) {
      CodeQualityAgent.instance = new CodeQualityAgent();
    }
    return CodeQualityAgent.instance;
  }

  // Common security vulnerability patterns
  private static readonly VULNERABILITY_PATTERNS: IVulnerabilityPattern[] = [
    // JavaScript/TypeScript vulnerabilities
    {
      pattern: /eval\s*\(/g,
      severity: 'high',
      description: 'Use of eval() can lead to code injection vulnerabilities',
      language: ProgrammingLanguage.JAVASCRIPT
    },
    {
      pattern: /innerHTML\s*=/g,
      severity: 'medium',
      description: 'Using innerHTML can lead to XSS vulnerabilities',
      language: ProgrammingLanguage.JAVASCRIPT
    },
    {
      pattern: /document\.write\s*\(/g,
      severity: 'medium',
      description: 'document.write can lead to XSS vulnerabilities',
      language: ProgrammingLanguage.JAVASCRIPT
    },
    // SQL injection patterns
    {
      pattern: /(?:execute|exec|query)\s*\([^)]*\$\{/g,
      severity: 'critical',
      description: 'Potential SQL injection vulnerability',
      language: 'all'
    },
    {
      pattern: /(?:execute|exec|query)\s*\([^)]*\+\s*(?:req|request|input|params)/gi,
      severity: 'critical',
      description: 'Potential SQL injection vulnerability with user input',
      language: 'all'
    },
    // Sensitive information
    {
      pattern: /(password|secret|api[_\s]*key|token|credentials?)[=:]\s*['"`][^'"`]+['"`]/gi,
      severity: 'critical',
      description: 'Hardcoded credentials or sensitive information',
      language: 'all'
    },
    // Python vulnerabilities
    {
      pattern: /pickle\.loads?\(/g,
      severity: 'high',
      description: 'Unsafe deserialization using pickle',
      language: ProgrammingLanguage.PYTHON
    },
    {
      pattern: /exec\s*\(/g,
      severity: 'high',
      description: 'Use of exec() can lead to code injection',
      language: ProgrammingLanguage.PYTHON
    },
    // Security misconfiguration
    {
      pattern: /(cors|CORS)[\s\n]*\{[\s\n]*origin[\s\n]*:[\s\n]*['"][*]['"]?/g,
      severity: 'medium',
      description: 'Overly permissive CORS configuration',
      language: 'all'
    }
  ];

  /**
   * Evaluate a GitHub solution for code quality
   * @param solution - The solution to evaluate
   * @returns Evaluation result with score and code quality metrics
   */
  public async evaluateInternal(solution: ISolution): Promise<ICodeQualityResult> {
    try {
      // Extract GitHub repository information
      const repoInfo = await this.extractGitHubRepoInfo(solution.submissionUrl);

      // Get any previous agent results from the solution object
      const previousResults = this.extractPreviousAgentResults(solution);

      logger.debug(`Starting code quality analysis for repository`, {
        solutionId: solution._id?.toString(),
        repo: `${repoInfo.owner}/${repoInfo.repo}`
      });

      // Analyze code quality metrics
      const repoAnalysis = await this.analyzeRepository(repoInfo, previousResults);

      // Calculate scores from the metrics
      const [scores, improvementAreas] = this.calculateScores(repoAnalysis);

      // Calculate weighted overall score
      const overallScore = Math.round(
        (scores.codeStyle * 0.2) +
        (scores.security * 0.3) +
        (scores.performance * 0.2) +
        (scores.maintainability * 0.3)
      );

      // Generate feedback based on scores
      const feedback = this.generateFeedback(
        overallScore,
        scores,
        improvementAreas,
        repoAnalysis
      );

      logger.info(`Completed code quality analysis`, {
        solutionId: solution._id?.toString(),
        repo: `${repoInfo.owner}/${repoInfo.repo}`,
        score: overallScore,
        codeStyle: scores.codeStyle,
        security: scores.security,
        performance: scores.performance,
        maintainability: scores.maintainability
      });

      return {
        score: overallScore,
        feedback,
        metadata: {
          codeStyle: scores.codeStyle,
          security: scores.security,
          performance: scores.performance,
          maintainability: scores.maintainability,
          vulnerabilities: repoAnalysis.vulnScanResults,
          improvementAreas,
          codeMetrics: {
            linesOfCode: repoAnalysis.linesOfCode,
            complexity: repoAnalysis.complexity,
            duplication: repoAnalysis.duplication,
            testCoverage: repoAnalysis.testCoverage
          },
          repoStats: {
            commitCount: repoAnalysis.commitCount,
            contributorCount: repoAnalysis.contributorCount,
            branchCount: repoAnalysis.branchCount
          },
          // Store LLM-specific analysis results
          llmAnalysis: repoAnalysis.llmAnalysis || undefined
        },
        evaluatedAt: new Date()
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorStack = error instanceof Error ? error.stack : undefined;

      logger.error(`Error in code quality evaluation`, {
        solutionId: solution._id?.toString(),
        error: errorMessage,
        stack: errorStack
      });

      // Return a default result on error
      return this.createErrorResult('Unable to analyze code quality: ' + errorMessage);
    }
  }

  /**
   * Extract previous agent results from the solution context
   * @param solution - The solution being evaluated
   * @returns Object containing previous agent results
   */
  private extractPreviousAgentResults(solution: ISolution): {
    spamFiltering?: any;
    requirementsCompliance?: any;
  } {
    const results: { 
      spamFiltering?: any;
      requirementsCompliance?: any;
    } = {};

    // In a production pipeline, we would have access to previous results
    // via a shared pipeline context or extracted from a database record
    // For this implementation, we'll look for previous results in the solution context
    if (solution.context && typeof solution.context === 'object') {
      if (solution.context.pipelineResults) {
        const pipelineResults = solution.context.pipelineResults;
        
        // Extract spam filtering results if available
        if (pipelineResults.spamFiltering) {
          results.spamFiltering = pipelineResults.spamFiltering;
        }
        
        // Extract requirements compliance results if available
        if (pipelineResults.requirementsCompliance) {
          results.requirementsCompliance = pipelineResults.requirementsCompliance;
        }
      } else if (solution.context.evaluationId) {
        // If we have an evaluationId, we could potentially fetch the results
        // from the database, but that would require database access
        logger.debug(`Evaluation ID found in solution context: ${solution.context.evaluationId}, but direct database access not implemented`);
      }
    }

    logger.debug(`Extracted previous agent results: ${Object.keys(results).length > 0 ? 'found data' : 'no data'}`);
    
    return results;
  }

  /**
   * Create a standardized error result
   * @param message - Error message
   * @returns Error result
   */
  private createErrorResult(message: string): ICodeQualityResult {
    return {
      score: 50,
      feedback: message,
      metadata: {
        codeStyle: 50,
        security: 50,
        performance: 50,
        maintainability: 50,
        vulnerabilities: [],
        improvementAreas: ['Could not complete analysis'],
        codeMetrics: {
          linesOfCode: 0,
          complexity: 0,
          duplication: 0
        },
        repoStats: {
          commitCount: 0,
          contributorCount: 0,
          branchCount: 0
        }
      },
      evaluatedAt: new Date()
    };
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

  /**
   * Determine the decision based on code quality metrics
   * @param result - The evaluation result
   * @returns Decision based on code quality scores
   */
  public determineDecision(result: ICodeQualityResult): EvaluationDecision {
    // Critical security vulnerabilities should be reviewed but not failed
    // as code quality failures should only happen if specifically required by the challenge
    const hasCriticalVulnerabilities = result.metadata.vulnerabilities.some(
      v => v.severity === 'critical'
    );

    if (hasCriticalVulnerabilities) {
      return EvaluationDecision.REVIEW;
    }

    // Unless explicitly instructed otherwise in the challenge requirements,
    // code quality issues should never cause a failure
    // We assume code quality requirements are not part of the challenge by default

    // Scores below 40 should be reviewed but not failed
    if (result.score < 40) {
      return EvaluationDecision.REVIEW;
    }

    // All other submissions pass this stage
    return EvaluationDecision.PASS;
  }

  /**
   * Analyze a GitHub repository for code quality metrics
   * @param repoInfo - Repository information
   * @param previousResults - Results from previous agents in the pipeline
   * @returns Comprehensive repository analysis
   */
  private async analyzeRepository(repoInfo: {
    owner: string;
    repo: string;
    url: string;
  }, previousResults?: {
    spamFiltering?: any;
    requirementsCompliance?: any;
  }): Promise<IRepositoryAnalysis> {
    const cacheKey = `${repoInfo.owner}/${repoInfo.repo}`;

    // Check cache first
    const cachedAnalysis = CodeQualityAgent.repositoryCache.get(cacheKey);
    if (cachedAnalysis && (Date.now() - cachedAnalysis.timestamp) < CACHE_TTL) {
      logger.debug(`Using cached repository analysis for ${cacheKey}`);
      return cachedAnalysis.analysis;
    }

    logger.debug(`Starting repository analysis for ${cacheKey}`);

    try {
      // Initialize repository analysis object
      const analysis: IRepositoryAnalysis = {
        files: [],
        directories: [],
        languages: new Map<ProgrammingLanguage, number>(),
        primaryLanguage: ProgrammingLanguage.UNKNOWN,
        testFiles: [],
        configFiles: [],
        vulnScanResults: [],
        totalSize: 0,
        issueCount: 0,
        linesOfCode: 0,
        commentLines: 0,
        complexity: 0,
        duplication: 0,
        testCoverage: 0,
        commitCount: 0,
        contributorCount: 0,
        branchCount: 0,
        llmAnalysis: {
          fileAnalysis: {},
          architectureAnalysis: null,
          enhancedVulnerabilities: false
        }
      };

      // Get repository structure first
      await this.fetchRepositoryStructure(repoInfo.owner, repoInfo.repo, '', analysis);

      // Get repository statistics
      await this.fetchRepositoryStats(repoInfo.owner, repoInfo.repo, analysis);

      // Determine primary language
      if (analysis.languages.size > 0) {
        let maxSize = 0;
        for (const [lang, size] of analysis.languages.entries()) {
          if (size > maxSize) {
            maxSize = size;
            analysis.primaryLanguage = lang;
          }
        }
      }

      // For significant files, fetch content and analyze
      const significantFiles = this.getSignificantFiles(analysis.files);

      // Fetch and analyze files in parallel with rate limiting
      let processedFiles = 0;
      const fileBatches = this.chunkArray(significantFiles, 5); // Process 5 files at a time

      for (const batch of fileBatches) {
        await Promise.all(batch.map(async file => {
          try {
            const content = await GitHubService.getFileContent(repoInfo.owner, repoInfo.repo, file.path);
            file.content = content;

            // Hash the content for duplication detection
            file.hash = crypto.createHash('md5').update(content).digest('hex');

            // Analyze file
            file.metrics = this.analyzeFileContent(file);

            // Look for vulnerabilities
            this.scanForVulnerabilities(file, analysis);

            // Update global metrics
            if (file.metrics) {
              analysis.linesOfCode += file.metrics.linesOfCode;
              analysis.commentLines += file.metrics.commentLines;
              analysis.complexity += file.metrics.complexity;
              analysis.issueCount += file.metrics.issues.length;
            }

            processedFiles++;
            if (processedFiles % 10 === 0) {
              logger.debug(`Processed ${processedFiles}/${significantFiles.length} files...`);
            }
          } catch (error) {
            logger.warn(`Error analyzing file ${file.path}`, {
              repo: `${repoInfo.owner}/${repoInfo.repo}`,
              error: error instanceof Error ? error.message : String(error)
            });
          }
        }));

        // Add small delay between batches to avoid rate limiting
        await setTimeout(200);
      }

      // Calculate duplication rate
      this.calculateDuplication(analysis);

      // Estimate test coverage
      analysis.testCoverage = this.estimateTestCoverage(analysis);

      // Enhanced analysis with LLM - analyze a subset of important files
      if (significantFiles.length > 0) {
        // Select most important files for LLM analysis
        const mostImportantFiles = significantFiles
          .filter(file => file.content && file.content.length > 0)
          .sort((a, b) => (b.metrics?.complexity || 0) - (a.metrics?.complexity || 0))
          .slice(0, 3); // Analyze top 3 most complex files

        // Ensure llmAnalysis is initialized
        if (!analysis.llmAnalysis) {
          analysis.llmAnalysis = {
            fileAnalysis: {},
            architectureAnalysis: null,
            enhancedVulnerabilities: false
          };
        }

        // Process files with LLM in parallel
        const llmFileResults = await Promise.all(
          mostImportantFiles.map(async file => {
            const fileAnalysis = await this.analyzeSingleFileWithLLM(file, repoInfo);
            return { file, analysis: fileAnalysis };
          })
        );

        // Store results and update metrics
        for (const result of llmFileResults) {
          // Ensure llmAnalysis.fileAnalysis exists
          if (analysis.llmAnalysis && !analysis.llmAnalysis.fileAnalysis) {
            analysis.llmAnalysis.fileAnalysis = {};
          }
          
          // Store LLM analysis
          if (analysis.llmAnalysis && analysis.llmAnalysis.fileAnalysis) {
            analysis.llmAnalysis.fileAnalysis[result.file.path] = result.analysis;
          }
          
          // Merge LLM-detected issues with file issues
          if (result.file.metrics) {
            result.file.metrics.issues = [
              ...result.file.metrics.issues,
              ...result.analysis.advancedIssues.filter(issue => 
                // Filter out potential duplicates
                !result.file.metrics?.issues.some(existing => 
                  existing.line === issue.line && 
                  existing.type === issue.type
                )
              )
            ];
            
            // Update file complexity considering LLM analysis
            result.file.metrics.complexity = Math.max(
              result.file.metrics.complexity,
              Math.round(result.analysis.complexity / 10)  // Scale LLM complexity to our metrics
            );
            
            // Update issue count
            analysis.issueCount += result.analysis.advancedIssues.length;
          }
        }

        // Perform architecture analysis if llmAnalysis is defined
        if (analysis.llmAnalysis) {
          analysis.llmAnalysis.architectureAnalysis = await this.analyzeRepositoryArchitectureWithLLM(
            repoInfo,
            analysis,
            previousResults
          );

          // Enhance vulnerability analysis if we have initial vulnerabilities
          if (analysis.vulnScanResults.length > 0) {
            const enhancedVulnerabilities = await this.enhanceVulnerabilityAnalysisWithLLM(
              repoInfo,
              analysis
            );
            
            // Update vulnerabilities with enhanced results
            if (enhancedVulnerabilities.length > analysis.vulnScanResults.length && analysis.llmAnalysis) {
              analysis.vulnScanResults = enhancedVulnerabilities;
              analysis.llmAnalysis.enhancedVulnerabilities = true;
            }
          }
        }
      }

      // Cache the analysis
      CodeQualityAgent.repositoryCache.set(cacheKey, {
        timestamp: Date.now(),
        analysis
      });

      logger.info(`Completed repository analysis for ${cacheKey}`, {
        files: analysis.files.length,
        primaryLanguage: analysis.primaryLanguage,
        issueCount: analysis.issueCount,
        vulnerabilities: analysis.vulnScanResults.length,
        llmEnhanced: analysis.llmAnalysis ? Object.keys(analysis.llmAnalysis.fileAnalysis || {}).length > 0 : false
      });

      return analysis;
    } catch (error) {
      logger.error(`Error in repository analysis`, {
        repo: `${repoInfo.owner}/${repoInfo.repo}`,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });

      throw error;
    }
  }

  /**
   * Fetch repository structure recursively
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param path - Current path
   * @param analysis - Analysis object to update
   */
  private async fetchRepositoryStructure(
    owner: string,
    repo: string,
    path: string,
    analysis: IRepositoryAnalysis
  ): Promise<void> {
    try {
      // Get repository contents using GitHubService
      const contents = await GitHubService.getRepositoryContents(owner, repo, path);

      // Process each item
      for (const item of contents) {
        if (item.type === 'file') {
          // Get file extension
          const extension = (() => {
            const idx = item.name.lastIndexOf('.');
            return idx !== -1 ? item.name.substring(idx).toLowerCase() : '';
          })();

          // Determine language based on extension
          const language = FILE_EXTENSION_TO_LANGUAGE[extension] || ProgrammingLanguage.UNKNOWN;

          // Create file info
          const fileInfo: IFileInfo = {
            path: item.path,
            name: item.name,
            extension,
            language,
            size: item.size,
            url: item.html_url
          };

          // Add to main files list
          analysis.files.push(fileInfo);

          // Update language statistics
          if (language !== ProgrammingLanguage.UNKNOWN) {
            const current = analysis.languages.get(language) || 0;
            analysis.languages.set(language, current + item.size);
          }

          // Update total size
          analysis.totalSize += item.size;

          // Check for specific file types
          if (this.isTestFile(item.path, item.name)) {
            analysis.testFiles.push(fileInfo);
          } else if (this.isConfigFile(item.name)) {
            analysis.configFiles.push(fileInfo);
          } else if (this.isReadmeFile(item.name)) {
            analysis.readmeFile = fileInfo;
          }
        } else if (item.type === 'dir') {
          // Add directory
          analysis.directories.push(item.path);

          // Recursively process directory
          await this.fetchRepositoryStructure(owner, repo, item.path, analysis);

          // Avoid hitting rate limits
          await setTimeout(100);
        }
      }
    } catch (error) {
      // Handle 404 errors gracefully
      if (error instanceof Error && 
          typeof error === 'object' && 
          error.hasOwnProperty('response') && 
          (error as any).response?.status === 404) {
        logger.debug(`Path not found in repository: ${path}`, {
          owner,
          repo
        });
        // This is not a critical error, just means the path doesn't exist
        return;
      }

      logger.error(`Error fetching repository structure`, {
        owner,
        repo,
        path,
        error: error instanceof Error ? error.message : String(error)
      });

      throw error;
    }
  }

  /**
   * Analyze file content for code quality metrics
   * @param file - File information with content
   * @returns File metrics
   */
  private analyzeFileContent(file: IFileInfo): IFileMetrics {
    if (!file.content) {
      return {
        linesOfCode: 0,
        commentLines: 0,
        complexity: 0,
        functions: 0,
        classes: 0,
        issues: []
      };
    }

    const content = file.content;
    const lines = content.split('\n');
    const linesOfCode = lines.length;

    // Count comment lines based on file type
    let commentLines = 0;
    let commentPattern: RegExp;
    let multilineCommentStart: RegExp;
    let multilineCommentEnd: RegExp;

    switch (file.language) {
      case ProgrammingLanguage.JAVASCRIPT:
      case ProgrammingLanguage.TYPESCRIPT:
        commentPattern = /^\s*(\/\/|\/\*|\*)/;
        multilineCommentStart = /\/\*/g;
        multilineCommentEnd = /\*\//g;
        break;
      case ProgrammingLanguage.PYTHON:
        commentPattern = /^\s*#/;
        multilineCommentStart = /"""/g;
        multilineCommentEnd = /"""/g;
        break;
      case ProgrammingLanguage.JAVA:
      case ProgrammingLanguage.CSHARP:
      case ProgrammingLanguage.KOTLIN:
        commentPattern = /^\s*(\/\/|\/\*|\*)/;
        multilineCommentStart = /\/\*/g;
        multilineCommentEnd = /\*\//g;
        break;
      default:
        commentPattern = /^\s*(\/\/|#|--|\/\*|\*)/;
        multilineCommentStart = /\/\*/g;
        multilineCommentEnd = /\*\//g;
    }

    // Count comment lines
    let inMultilineComment = false;
    for (const line of lines) {
      if (inMultilineComment) {
        commentLines++;
        if (line.match(multilineCommentEnd)) {
          inMultilineComment = false;
        }
      } else if (line.match(commentPattern)) {
        commentLines++;
      } else if (line.match(multilineCommentStart)) {
        commentLines++;
        inMultilineComment = true;
      }
    }

    // Count functions (very basic detection)
    const functionPattern = file.language === ProgrammingLanguage.PYTHON
      ? /\s*def\s+\w+\s*\(/g
      : /\s*(function|async|class|method)\s+\w+\s*\(|(\w+)\s*:\s*function|\(\s*\)\s*=>/g;

    const functionMatches = content.match(functionPattern) || [];
    const functions = functionMatches.length;

    // Count classes (very basic detection)
    const classPattern = file.language === ProgrammingLanguage.PYTHON
      ? /\s*class\s+\w+/g
      : /\s*(class|interface)\s+\w+/g;

    const classMatches = content.match(classPattern) || [];
    const classes = classMatches.length;

    // Estimate complexity (very basic - count branching statements)
    const complexityPattern = /\s*(if|else|for|while|switch|catch|case|&&|\|\|)/g;
    const complexityMatches = content.match(complexityPattern) || [];
    const complexity = complexityMatches.length;

    // Detect code issues
    const issues: ICodeIssue[] = [];

    // Check for long functions (>50 lines is considered long)
    const functionRegex = file.language === ProgrammingLanguage.PYTHON
      ? /def\s+(\w+)\s*\(/g
      : /function\s+(\w+)\s*\(/g;

    let match;
    let inFunction = false;
    let functionStartLine = -1;
    let currentFunction = '';
    let braceCount = 0;

    // Very basic function boundary detection
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (!inFunction) {
        functionRegex.lastIndex = 0;
        match = functionRegex.exec(line);
        if (match) {
          inFunction = true;
          functionStartLine = i;
          currentFunction = match[1];

          if (file.language !== ProgrammingLanguage.PYTHON) {
            braceCount = 0;
            braceCount += (line.match(/{/g) || []).length;
            braceCount -= (line.match(/}/g) || []).length;
          }
        }
      } else {
        if (file.language === ProgrammingLanguage.PYTHON) {
          if (line.match(/^\s*def\s+/) || i === lines.length - 1) {
            // Python function ended (new function or end of file)
            const functionLength = i - functionStartLine;
            if (functionLength > 50) {
              issues.push({
                type: 'maintainability',
                severity: 'warning',
                line: functionStartLine + 1,
                message: `Function '${currentFunction}' is too long (${functionLength} lines)`,
                rule: 'function-length'
              });
            }
            inFunction = false;
          }
        } else {
          // For C-style languages, count braces
          braceCount += (line.match(/{/g) || []).length;
          braceCount -= (line.match(/}/g) || []).length;

          if (braceCount === 0) {
            // Function ended
            const functionLength = i - functionStartLine + 1;
            if (functionLength > 50) {
              issues.push({
                type: 'maintainability',
                severity: 'warning',
                line: functionStartLine + 1,
                message: `Function '${currentFunction}' is too long (${functionLength} lines)`,
                rule: 'function-length'
              });
            }
            inFunction = false;
          }
        }
      }
    }

    // Check for long lines (>100 chars)
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 100) {
        issues.push({
          type: 'style',
          severity: 'info',
          line: i + 1,
          message: 'Line is too long (exceeds 100 characters)',
          rule: 'line-length'
        });
      }
    }

    // Check for trailing whitespace
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].match(/\s+$/)) {
        issues.push({
          type: 'style',
          severity: 'info',
          line: i + 1,
          message: 'Line contains trailing whitespace',
          rule: 'no-trailing-whitespace'
        });
      }
    }

    // Return metrics
    return {
      linesOfCode,
      commentLines,
      complexity,
      functions,
      classes,
      issues
    };
  }

  /**
   * Scan file for vulnerabilities
   * @param file - File to scan
   * @param analysis - Analysis to update with findings
   */
  private scanForVulnerabilities(file: IFileInfo, analysis: IRepositoryAnalysis): void {
    if (!file.content) {
      return;
    }

    // Get relevant vulnerability patterns for this file
    const patterns = CodeQualityAgent.VULNERABILITY_PATTERNS.filter(
      pattern => pattern.language === 'all' || pattern.language === file.language
    );

    // Scan for each pattern
    for (const pattern of patterns) {
      pattern.pattern.lastIndex = 0; // Reset regex
      const matches = file.content.match(pattern.pattern);

      if (matches) {
        // For each match, add a vulnerability
        for (const match of matches) {
          // Find the line number
          let lineNumber = 1;
          let pos = file.content.indexOf(match);
          if (pos !== -1) {
            lineNumber = file.content.substring(0, pos).split('\n').length;
          }

          // Add to vulnerability list
          const vulnResult: IVulnerabilityResult = {
            severity: pattern.severity,
            description: pattern.description,
            location: `${file.path}:${lineNumber}`,
            languageSpecific: pattern.language !== 'all',
            remediation: this.getRemediationAdvice(pattern)
          };

          analysis.vulnScanResults.push(vulnResult);

          // Also add as a file issue
          if (file.metrics) {
            file.metrics.issues.push({
              type: 'security',
              severity: this.mapVulnerabilitySeverityToIssueSeverity(pattern.severity),
              line: lineNumber,
              message: pattern.description,
              rule: 'security-vulnerability'
            });
          }
        }
      }
    }
  }

  /**
   * Calculate code duplication rate
   * @param analysis - Repository analysis to update
   */
  private calculateDuplication(analysis: IRepositoryAnalysis): void {
    // Group files by language for more accurate duplication detection
    const filesByLanguage = new Map<ProgrammingLanguage, IFileInfo[]>();

    for (const file of analysis.files) {
      if (
        file.content &&
        file.hash &&
        file.language !== undefined &&
        file.language !== ProgrammingLanguage.UNKNOWN
      ) {
        const files = filesByLanguage.get(file.language) || [];
        files.push(file);
        filesByLanguage.set(file.language, files);
      }
    }

    // For each language, check for duplicate content
    let duplicatedLines = 0;
    let totalLines = 0;

    // First, check for exact file duplicates using hashes
    const fileHashes = new Map<string, string[]>();

    for (const file of analysis.files) {
      if (file.hash) {
        const paths = fileHashes.get(file.hash) || [];
        paths.push(file.path);
        fileHashes.set(file.hash, paths);

        // Count total lines
        if (file.metrics) {
          totalLines += file.metrics.linesOfCode;
        }
      }
    }

    // Count duplicated files
    for (const [hash, paths] of fileHashes.entries()) {
      if (paths.length > 1) {
        // Found duplicate files
        const duplicateFile = analysis.files.find(f => f.hash === hash);
        if (duplicateFile && duplicateFile.metrics) {
          // Count all duplicated lines (excluding the first file)
          duplicatedLines += duplicateFile.metrics.linesOfCode * (paths.length - 1);
        }
      }
    }

    // Calculate duplication percentage
    analysis.duplication = totalLines > 0 ? Math.round((duplicatedLines / totalLines) * 100) : 0;
  }

  /**
   * Estimate test coverage based on repository structure
   * @param analysis - Repository analysis
   * @returns Estimated test coverage (0-100)
   */
  private estimateTestCoverage(analysis: IRepositoryAnalysis): number {
    // Very basic heuristic: ratio of test files to total files
    const testFiles = analysis.testFiles.length;
    const totalFiles = analysis.files.length - analysis.configFiles.length;

    if (totalFiles === 0) {
      return 0;
    }

    // Base coverage on test file ratio
    let coverage = Math.min(100, Math.round((testFiles / totalFiles) * 100));

    // Adjust based on test complexity
    let testComplexity = 0;
    let testLines = 0;

    for (const file of analysis.testFiles) {
      if (file.metrics) {
        testComplexity += file.metrics.complexity;
        testLines += file.metrics.linesOfCode;
      }
    }

    // If we have test metrics, adjust coverage based on test complexity
    if (testLines > 0) {
      const complexityRatio = testComplexity / testLines;

      // More complex tests likely have better coverage
      if (complexityRatio > 0.1) {
        coverage = Math.min(100, coverage + 10);
      } else if (complexityRatio < 0.05) {
        coverage = Math.max(0, coverage - 10);
      }
    }

    return coverage;
  }

  /**
   * Calculate scores from analysis metrics
   * @param analysis - Repository analysis
   * @returns Scores and improvement areas
   */
  private calculateScores(analysis: IRepositoryAnalysis): [
    {
      codeStyle: number;
      security: number;
      performance: number;
      maintainability: number;
    },
    string[]
  ] {
    // Initialize scores
    const scores = {
      codeStyle: 0,
      security: 0,
      performance: 0,
      maintainability: 0
    };

    const improvementAreas: string[] = [];

    // Calculate code style score
    let styleIssues = 0;
    for (const file of analysis.files) {
      if (file.metrics) {
        styleIssues += file.metrics.issues.filter(i => i.type === 'style').length;
      }
    }

    // Style score based on issue density
    const styleIssueDensity = analysis.linesOfCode > 0
      ? (styleIssues / analysis.linesOfCode)
      : 0;

    if (styleIssueDensity <= 0.01) {
      scores.codeStyle = 90; // Excellent
    } else if (styleIssueDensity <= 0.05) {
      scores.codeStyle = 75; // Good
    } else if (styleIssueDensity <= 0.1) {
      scores.codeStyle = 60; // Acceptable
    } else {
      scores.codeStyle = 40; // Poor
      improvementAreas.push('Code style and formatting');
    }

    // Security score
    const criticalVulns = analysis.vulnScanResults.filter(v => v.severity === 'critical').length;
    const highVulns = analysis.vulnScanResults.filter(v => v.severity === 'high').length;
    const mediumVulns = analysis.vulnScanResults.filter(v => v.severity === 'medium').length;

    if (criticalVulns > 0) {
      scores.security = 10; // Critical security issues
      improvementAreas.push('Critical security vulnerabilities');
    } else if (highVulns > 0) {
      scores.security = 30; // High security issues
      improvementAreas.push('High-severity security vulnerabilities');
    } else if (mediumVulns > 0) {
      scores.security = 50; // Medium security issues
      improvementAreas.push('Medium-severity security vulnerabilities');
    } else if (analysis.vulnScanResults.length > 0) {
      scores.security = 70; // Low security issues
      improvementAreas.push('Minor security concerns');
    } else {
      scores.security = 90; // No security issues detected
    }

    // Performance score
    let perfIssues = 0;
    for (const file of analysis.files) {
      if (file.metrics) {
        perfIssues += file.metrics.issues.filter(i => i.type === 'performance').length;
      }
    }

    // Performance score based on issue count and complexity
    const complexityFactor = analysis.linesOfCode > 0
      ? (analysis.complexity / analysis.linesOfCode)
      : 0;

    if (perfIssues === 0 && complexityFactor < 0.05) {
      scores.performance = 90; // Excellent
    } else if (perfIssues < 5 && complexityFactor < 0.1) {
      scores.performance = 75; // Good
    } else if (perfIssues < 10 && complexityFactor < 0.2) {
      scores.performance = 60; // Acceptable
    } else {
      scores.performance = 40; // Poor
      improvementAreas.push('Code performance and complexity');
    }

    // Maintainability score
    const duplicationPenalty = analysis.duplication > 20 ? 30 :
      analysis.duplication > 10 ? 15 :
        analysis.duplication > 5 ? 5 : 0;

    let maintIssues = 0;
    for (const file of analysis.files) {
      if (file.metrics) {
        maintIssues += file.metrics.issues.filter(i => i.type === 'maintainability').length;
      }
    }

    const hasReadme = analysis.readmeFile !== undefined;
    const readmePenalty = hasReadme ? 0 : 10;

    if (maintIssues === 0 && duplicationPenalty === 0 && readmePenalty === 0) {
      scores.maintainability = 90; // Excellent
    } else if (maintIssues < 5 && duplicationPenalty <= 5 && readmePenalty === 0) {
      scores.maintainability = 75; // Good
    } else if (maintIssues < 10 && duplicationPenalty <= 15) {
      scores.maintainability = 60; // Acceptable
    } else {
      scores.maintainability = 40; // Poor

      if (duplicationPenalty > 0) {
        improvementAreas.push(`Code duplication (${analysis.duplication}%)`);
      }

      if (readmePenalty > 0) {
        improvementAreas.push('Missing documentation (README)');
      }

      if (maintIssues > 10) {
        improvementAreas.push('Code maintainability');
      }
    }

    // Incorporate LLM analysis if available
    if (analysis.llmAnalysis) {
      // Adjust security score based on LLM-enhanced vulnerability analysis
      if (analysis.llmAnalysis.enhancedVulnerabilities) {
        // If LLM found additional vulnerabilities, adjust security score
        // but don't decrease it below current level
        const llmVulnCount = analysis.vulnScanResults.filter(v => 'source' in v && v.source === 'llm-analysis').length;
        if (llmVulnCount > 0) {
          // Adjust score based on number of additional vulnerabilities found
          if (llmVulnCount >= 3) {
            scores.security = Math.min(scores.security, 40); // More severe adjustment for multiple issues
            improvementAreas.push('LLM-detected security concerns');
          } else {
            scores.security = Math.min(scores.security, 60); // Minor adjustment
          }
        }
      }

      // Incorporate architecture analysis
      if (analysis.llmAnalysis.architectureAnalysis) {
        const archAnalysis = analysis.llmAnalysis.architectureAnalysis;
        
        // Adjust maintainability score based on architecture quality
        // Use a weighted average with the existing maintainability score
        scores.maintainability = Math.round(
          scores.maintainability * 0.7 + (archAnalysis.architectureScore * 0.3)
        );
        
        // Add architecture-related improvement areas if score is low
        if (archAnalysis.architectureScore < 50) {
          improvementAreas.push('Architecture design');
          
          // Add specific recommendations if available
          if (archAnalysis.architectureRecommendations?.length > 0) {
            improvementAreas.push(archAnalysis.architectureRecommendations[0]);
          }
        }
      }
      
      // Incorporate file-level analysis
      const fileAnalysisKeys = Object.keys(analysis.llmAnalysis.fileAnalysis || {});
      if (fileAnalysisKeys.length > 0) {
        // Calculate average LLM-detected complexity across analyzed files
        let totalComplexity = 0;
        let totalMaintainability = 0;
        let filesWithAnalysis = 0;
        
        for (const key of fileAnalysisKeys) {
          const fileAnalysis = analysis.llmAnalysis.fileAnalysis[key];
          totalComplexity += fileAnalysis.complexity;
          totalMaintainability += fileAnalysis.maintainability;
          filesWithAnalysis++;
        }
        
        if (filesWithAnalysis > 0) {
          const avgComplexity = totalComplexity / filesWithAnalysis;
          const avgMaintainability = totalMaintainability / filesWithAnalysis;
          
          // Adjust performance score based on LLM-detected complexity
          // Use a weighted average with the existing performance score
          if (avgComplexity > 0) {
            const llmComplexityScore = 100 - avgComplexity; // Convert complexity to score (higher is better)
            scores.performance = Math.round(
              scores.performance * 0.7 + (llmComplexityScore * 0.3)
            );
          }
          
          // Adjust maintainability score based on LLM-detected maintainability
          // Use a weighted average with the existing maintainability score
          if (avgMaintainability > 0) {
            scores.maintainability = Math.round(
              scores.maintainability * 0.7 + (avgMaintainability * 0.3)
            );
          }
        }
      }
    }

    // Return scores and improvement areas
    return [scores, improvementAreas];
  }

  /**
   * Generate feedback based on analysis
   * @param overallScore - Overall quality score
   * @param scores - Individual component scores
   * @param improvementAreas - Areas needing improvement
   * @param analysis - Repository analysis
   * @returns Human-readable feedback
   */
  private generateFeedback(
    overallScore: number,
    scores: {
      codeStyle: number;
      security: number;
      performance: number;
      maintainability: number;
    },
    improvementAreas: string[],
    analysis: IRepositoryAnalysis
  ): string {
    let feedback = `Code quality analysis: Overall quality score ${overallScore}/100. `;

    if (overallScore >= 80) {
      feedback += 'The code demonstrates high quality with good practices.';
    } else if (overallScore >= 60) {
      feedback += 'The code quality is satisfactory but has room for improvement.';
    } else {
      feedback += 'The code quality needs significant improvement.';
    }

    // Add specific feedback for critical issues
    const criticalVulns = analysis.vulnScanResults.filter(v => v.severity === 'critical');
    if (criticalVulns.length > 0) {
      feedback += ` Found ${criticalVulns.length} critical security vulnerabilities that should be addressed immediately.`;
    }

    // Add specific feedback for improvement areas
    if (improvementAreas.length > 0) {
      feedback += ` Focus on improving: ${improvementAreas.join(', ')}.`;
    }

    // Add language-specific feedback
    if (analysis.primaryLanguage !== ProgrammingLanguage.UNKNOWN) {
      feedback += ` Primary language detected: ${analysis.primaryLanguage}.`;
    }

    // Incorporate LLM analysis insights if available
    if (analysis.llmAnalysis) {
      // Add architecture insights
      if (analysis.llmAnalysis.architectureAnalysis) {
        const archAnalysis = analysis.llmAnalysis.architectureAnalysis;
        
        // Add architecture score
        feedback += ` Architecture quality score: ${archAnalysis.architectureScore}/100.`;
        
        // Add design patterns if detected
        if (archAnalysis.designPatterns && archAnalysis.designPatterns.length > 0) {
          feedback += ` Design patterns identified: ${archAnalysis.designPatterns.slice(0, 3).join(', ')}${archAnalysis.designPatterns.length > 3 ? '...' : ''}.`;
        }
        
        // Add strengths
        if (archAnalysis.strengths && archAnalysis.strengths.length > 0) {
          feedback += ` Key strengths: ${archAnalysis.strengths[0]}${archAnalysis.strengths.length > 1 ? '...' : ''}.`;
        }
        
        // Add top recommendation
        if (archAnalysis.architectureRecommendations && archAnalysis.architectureRecommendations.length > 0) {
          feedback += ` Top recommendation: ${archAnalysis.architectureRecommendations[0]}.`;
        }
      }
      
      // Add insights from file analysis
      const fileAnalysisKeys = Object.keys(analysis.llmAnalysis.fileAnalysis || {});
      if (fileAnalysisKeys.length > 0) {
        // Collect best practices across all analyzed files
        const allBestPractices = new Set<string>();
        for (const key of fileAnalysisKeys) {
          const fileAnalysis = analysis.llmAnalysis.fileAnalysis[key];
          fileAnalysis.bestPractices.forEach(practice => allBestPractices.add(practice));
        }
        
        // Add best practices if found
        if (allBestPractices.size > 0) {
          const practices = Array.from(allBestPractices).slice(0, 2);
          feedback += ` Positive practices: ${practices.join(', ')}${allBestPractices.size > 2 ? '...' : ''}.`;
        }
      }
    }

    return feedback;
  }

  /**
   * Get remediation advice for a vulnerability
   * @param pattern - Vulnerability pattern
   * @returns Remediation advice string
   */
  private getRemediationAdvice(pattern: IVulnerabilityPattern): string {
    // Common security remediation advice
    switch (pattern.description) {
      case 'Use of eval() can lead to code injection vulnerabilities':
        return 'Replace eval() with safer alternatives that do not execute arbitrary code';

      case 'Using innerHTML can lead to XSS vulnerabilities':
        return 'Use textContent instead of innerHTML, or sanitize HTML input with a dedicated library';

      case 'Potential SQL injection vulnerability':
        return 'Use parameterized queries or prepared statements instead of string concatenation';

      case 'Hardcoded credentials or sensitive information':
        return 'Move sensitive data to environment variables or a secure configuration system';

      case 'Unsafe deserialization using pickle':
        return 'Avoid using pickle with untrusted data; consider alternatives like JSON';

      case 'Overly permissive CORS configuration':
        return 'Restrict CORS to specific origins rather than using wildcard (*) permissions';

      default:
        return 'Review and refactor code to follow security best practices';
    }
  }

  /**
   * Maps vulnerability severity to issue severity
   * @param vulnSeverity - Vulnerability severity
   * @returns Issue severity
   */
  private mapVulnerabilitySeverityToIssueSeverity(
    vulnSeverity: 'low' | 'medium' | 'high' | 'critical'
  ): 'info' | 'warning' | 'error' | 'critical' {
    switch (vulnSeverity) {
      case 'critical': return 'critical';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
    }
  }

  /**
   * Determine if a file is a test file
   * @param path - File path
   * @param name - File name
   * @returns Whether the file is a test file
   */
  private isTestFile(path: string, name: string): boolean {
    return path.includes('/test/') ||
      path.includes('/tests/') ||
      path.includes('/spec/') ||
      path.includes('/specs/') ||
      name.includes('test') ||
      name.includes('spec') ||
      name.startsWith('test_') ||
      name.endsWith('_test') ||
      name.endsWith('.test.') ||
      name.endsWith('.spec.');
  }

  /**
   * Determine if a file is a configuration file
   * @param name - File name
   * @returns Whether the file is a configuration file
   */
  private isConfigFile(name: string): boolean {
    const configFiles = [
      'package.json',
      'tsconfig.json',
      '.eslintrc',
      '.prettierrc',
      '.gitignore',
      '.dockerignore',
      'Dockerfile',
      'docker-compose.yml',
      'requirements.txt',
      'setup.py',
      'Gemfile',
      'pom.xml',
      'build.gradle',
      '.env.example'
    ];

    return configFiles.includes(name) ||
      name.endsWith('.config.js') ||
      name.endsWith('.json') ||
      name.endsWith('.yml') ||
      name.endsWith('.yaml');
  }

  /**
   * Determine if a file is a README file
   * @param name - File name
   * @returns Whether the file is a README file
   */
  private isReadmeFile(name: string): boolean {
    return name.toLowerCase() === 'readme.md' ||
      name.toLowerCase() === 'readme.txt' ||
      name.toLowerCase() === 'readme';
  }

  /**
   * Get significant files to analyze deeply
   * @param files - All repository files
   * @returns Files that should be analyzed
   */
  private getSignificantFiles(files: IFileInfo[]): IFileInfo[] {
    // Define max file size to analyze (100KB)
    const MAX_FILE_SIZE = 100 * 1024;

    // Define extensions to skip
    const SKIP_EXTENSIONS = [
      '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
      '.ttf', '.woff', '.woff2', '.eot',
      '.min.js', '.min.css',
      '.lock', '.map'
    ];

    // Filter significant files
    return files.filter(file => {
      // Skip files that are too large
      if (file.size > MAX_FILE_SIZE) {
        return false;
      }

      // Skip binary and generated files
      for (const ext of SKIP_EXTENSIONS) {
        if (file.extension === ext || file.name.endsWith(ext)) {
          return false;
        }
      }

      // Include only code files
      return file.language !== ProgrammingLanguage.UNKNOWN;
    });
  }

  /**
   * Split array into chunks
   * @param array - Array to split
   * @param chunkSize - Chunk size
   * @returns Array of chunks
   */
  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Fetch repository statistics from GitHub API
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param analysis - Analysis object to update with stats
   */
  private async fetchRepositoryStats(
    owner: string,
    repo: string,
    analysis: IRepositoryAnalysis
  ): Promise<void> {
    try {
      const stats = await GitHubService.getRepositoryStats(owner, repo);
      
      // Update analysis with stats
      analysis.commitCount = stats.commitCount;
      analysis.contributorCount = stats.contributorCount;
      analysis.branchCount = stats.branchCount;
    } catch (error) {
      // Log error but continue - stats are non-critical
      logger.warn(`Error fetching repository stats`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Use default values
      analysis.commitCount = 1;
      analysis.contributorCount = 1;
      analysis.branchCount = 1;
    }
  }

  /**
   * Perform deep code analysis using LLM for a specific file
   * @param file - File to analyze
   * @param repoInfo - Repository information
   * @returns Enhanced code analysis with LLM insights
   */
  private async analyzeSingleFileWithLLM(
    file: IFileInfo,
    repoInfo: { owner: string; repo: string }
  ): Promise<{
    advancedIssues: ICodeIssue[];
    complexity: number;
    maintainability: number;
    bestPractices: string[];
    securityInsights: string[];
  }> {
    if (!file.content || file.content.trim().length === 0) {
      return {
        advancedIssues: [],
        complexity: 0,
        maintainability: 0,
        bestPractices: [],
        securityInsights: []
      };
    }

    try {
      // Prepare system prompt
      const systemPrompt = `You are a code quality analysis expert. Analyze the following ${file.language} code and provide:
1. A list of code issues with line numbers, severity (info/warning/error/critical), and explanations
2. A complexity score from 0-100 (higher means more complex)
3. A maintainability score from 0-100 (higher means more maintainable)
4. Best practices that are followed in the code
5. Security insights and potential vulnerabilities

Format your response as valid JSON with the following structure:
{
  "issues": [{"line": number, "severity": "info|warning|error|critical", "message": "string", "type": "style|performance|maintainability|security"}],
  "complexity": number,
  "maintainability": number,
  "bestPractices": ["string"],
  "securityInsights": ["string"]
}`;

      // Prepare the LLM request
      const request: ILLMTextRequest = {
        model: "gpt-4o", // Using most capable model for code analysis
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `File: ${file.path}\n\nCode:\n\`\`\`${file.language}\n${file.content}\n\`\`\`` }
        ],
        temperature: 0.1,
        maxTokens: 2048,
        jsonMode: true,
        metadata: {
          source: "CodeQualityAgent",
          file: file.path,
          repo: `${repoInfo.owner}/${repoInfo.repo}`
        }
      };

      // Call LLM service
      const response = await this.llmService.generateText(request);
      
      // Parse response
      try {
        const result = JSON.parse(response.text);
        
        // Convert LLM response issues to our internal format
        const advancedIssues = (result.issues || []).map((issue: any) => ({
          type: issue.type || "maintainability",
          severity: issue.severity || "info",
          line: issue.line || 1,
          message: issue.message || "Code issue detected",
          rule: `llm-${issue.type || "code-quality"}`
        }));
        
        return {
          advancedIssues,
          complexity: result.complexity || 50,
          maintainability: result.maintainability || 50,
          bestPractices: result.bestPractices || [],
          securityInsights: result.securityInsights || []
        };
      } catch (parseError) {
        logger.warn(`Error parsing LLM response for file ${file.path}`, {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          text: response.text.substring(0, 200) + "..."
        });
        
        return {
          advancedIssues: [],
          complexity: 50,
          maintainability: 50,
          bestPractices: [],
          securityInsights: []
        };
      }
    } catch (error) {
      logger.warn(`Error in LLM code analysis for file ${file.path}`, {
        error: error instanceof Error ? error.message : String(error)
      });
      
      return {
        advancedIssues: [],
        complexity: 50,
        maintainability: 50,
        bestPractices: [],
        securityInsights: []
      };
    }
  }

  /**
   * Analyze overall repository architecture using LLM
   * @param repoInfo - Repository information
   * @param analysis - Current repository analysis
   * @param previousResults - Results from previous agents in the pipeline
   * @returns Enhanced architecture analysis
   */
  private async analyzeRepositoryArchitectureWithLLM(
    repoInfo: { owner: string; repo: string },
    analysis: IRepositoryAnalysis,
    previousResults?: {
      spamFiltering?: any;
      requirementsCompliance?: any;
    }
  ): Promise<{
    architectureScore: number;
    designPatterns: string[];
    architectureRecommendations: string[];
    strengths: string[];
    weaknesses: string[];
  }> {
    try {
      // Create a repository structure summary
      const directoryStructure = analysis.directories.slice(0, 20).join('\n');
      const fileTypes = Array.from(analysis.languages.entries())
        .map(([lang, size]) => `${lang}: ${size} bytes`)
        .join('\n');
      
      // Get important file summaries
      const importantFiles = this.getSignificantFiles(analysis.files).slice(0, 5);
      const fileSummaries = importantFiles.map(file => 
        `${file.path} (${file.language}): ${file.content ? file.content.substring(0, 150) + '...' : 'No content'}`
      ).join('\n\n');
      
      // Create system prompt
      let systemPrompt = `You are a software architecture expert. Analyze the following repository structure and provide insights on the architecture quality:

1. An overall architecture score from 0-100
2. Identified design patterns
3. Architecture recommendations
4. Architectural strengths
5. Architectural weaknesses

Format your response as JSON:
{
  "architectureScore": number,
  "designPatterns": ["string"],
  "architectureRecommendations": ["string"],
  "strengths": ["string"],
  "weaknesses": ["string"]
}`;

      // Include previous analysis results if available
      let previousAnalysisInsights = "";
      if (previousResults?.requirementsCompliance?.result) {
        const reqResults = previousResults.requirementsCompliance.result;
        previousAnalysisInsights += `\nRequirements compliance score: ${reqResults.score}/100\n`;
        if (reqResults.metadata?.requirements) {
          previousAnalysisInsights += `Requirements met: ${reqResults.metadata.requirements.join(", ")}\n`;
        }
      }

      // Prepare the LLM request
      const request: ILLMTextRequest = {
        model: "gpt-4o", // Using most capable model for architecture analysis
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Repository: ${repoInfo.owner}/${repoInfo.repo}

Directory Structure:
${directoryStructure}

Languages:
${fileTypes}

${previousAnalysisInsights}

Key File Samples:
${fileSummaries}
` }
        ],
        temperature: 0.2,
        maxTokens: 2048,
        jsonMode: true,
        metadata: {
          source: "CodeQualityAgent",
          analysisType: "architecture",
          repo: `${repoInfo.owner}/${repoInfo.repo}`
        }
      };

      // Call LLM service
      const response = await this.llmService.generateText(request);
      
      // Parse response
      try {
        const result = JSON.parse(response.text);
        return {
          architectureScore: result.architectureScore || 50,
          designPatterns: result.designPatterns || [],
          architectureRecommendations: result.architectureRecommendations || [],
          strengths: result.strengths || [],
          weaknesses: result.weaknesses || []
        };
      } catch (parseError) {
        logger.warn(`Error parsing LLM architecture analysis`, {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          text: response.text.substring(0, 200) + "..."
        });
        
        return {
          architectureScore: 50,
          designPatterns: [],
          architectureRecommendations: [],
          strengths: [],
          weaknesses: []
        };
      }
    } catch (error) {
      logger.warn(`Error in LLM architecture analysis`, {
        repo: `${repoInfo.owner}/${repoInfo.repo}`,
        error: error instanceof Error ? error.message : String(error)
      });
      
      return {
        architectureScore: 50,
        designPatterns: [],
        architectureRecommendations: [],
        strengths: [],
        weaknesses: []
      };
    }
  }

  /**
   * Enhanced vulnerability scan with LLM
   * @param repoInfo - Repository information
   * @param analysis - Current repository analysis
   * @returns Enhanced vulnerability results
   */
  private async enhanceVulnerabilityAnalysisWithLLM(
    repoInfo: { owner: string; repo: string },
    analysis: IRepositoryAnalysis
  ): Promise<IVulnerabilityResult[]> {
    // Start with static analysis results
    const staticResults = [...analysis.vulnScanResults];
    
    // Only process if we have significant vulnerabilities or a complex project
    if (staticResults.length < 2 && analysis.files.length < 20) {
      return staticResults;
    }
    
    try {
      // Create vulnerability summary
      const vulnSummary = staticResults.map(vuln => 
        `Location: ${vuln.location}, Severity: ${vuln.severity}, Description: ${vuln.description}`
      ).join('\n');
      
      // Get security-relevant files
      const securityFiles = analysis.files.filter(file => {
        const path = file.path.toLowerCase();
        return path.includes('auth') || 
               path.includes('secur') || 
               path.includes('login') || 
               path.includes('password') ||
               path.includes('crypt') ||
               path.includes('permission');
      });
      
      // Get content of security-relevant files
      const securityFileContents = securityFiles.slice(0, 3).map(file => 
        `${file.path}:\n${file.content ? file.content.substring(0, 500) + '...' : 'No content'}`
      ).join('\n\n');
      
      // Create system prompt
      const systemPrompt = `You are a security expert specializing in code security. Review the detected vulnerabilities and security-relevant files in this repository. Identify any additional security concerns or provide deeper insights on existing vulnerabilities.

Format your response as JSON:
{
  "enhancedVulnerabilities": [
    {
      "severity": "low|medium|high|critical",
      "description": "string",
      "location": "string (file:line)",
      "remediation": "string",
      "cwe": "string (optional CWE ID)"
    }
  ]
}`;

      // Prepare the LLM request
      const request: ILLMTextRequest = {
        model: "gpt-4o", // Using most capable model for security analysis
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Repository: ${repoInfo.owner}/${repoInfo.repo}

Detected Vulnerabilities:
${vulnSummary || "No vulnerabilities detected by static analysis."}

Security-Relevant Files:
${securityFileContents || "No security-relevant files found."}

Primary language: ${analysis.primaryLanguage}
` }
        ],
        temperature: 0.2,
        maxTokens: 2048,
        jsonMode: true,
        metadata: {
          source: "CodeQualityAgent",
          analysisType: "security",
          repo: `${repoInfo.owner}/${repoInfo.repo}`
        }
      };

      // Call LLM service
      const response = await this.llmService.generateText(request);
      
      // Parse response
      try {
        const result = JSON.parse(response.text);
        
        if (result.enhancedVulnerabilities && Array.isArray(result.enhancedVulnerabilities)) {
          // Convert LLM response to our internal format
          const llmVulns = result.enhancedVulnerabilities.map((vuln: any) => ({
            severity: vuln.severity || "medium",
            description: `${vuln.description}${vuln.cwe ? ` (${vuln.cwe})` : ''}`,
            location: vuln.location || "Unknown",
            remediation: vuln.remediation || "Review and fix security issue",
            languageSpecific: false,
            source: "llm-analysis"
          }));
          
          // Merge with static results (avoid duplicates)
          const allVulns = [...staticResults];
          
          for (const llmVuln of llmVulns) {
            // Check if this might be duplicate
            const isDuplicate = staticResults.some(
              staticVuln => 
                staticVuln.location === llmVuln.location || 
                staticVuln.description.includes(llmVuln.description.substring(0, 10))
            );
            
            if (!isDuplicate) {
              allVulns.push(llmVuln);
            }
          }
          
          return allVulns;
        }
        
        return staticResults;
      } catch (parseError) {
        logger.warn(`Error parsing LLM vulnerability analysis`, {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          text: response.text.substring(0, 200) + "..."
        });
        
        return staticResults;
      }
    } catch (error) {
      logger.warn(`Error in LLM vulnerability analysis`, {
        repo: `${repoInfo.owner}/${repoInfo.repo}`,
        error: error instanceof Error ? error.message : String(error)
      });
      
      return staticResults;
    }
  }
} 

// Export singleton instance for use in routes
export const codeQualityAgent = CodeQualityAgent.getInstance();