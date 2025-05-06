import { AIAgentBase } from '../AIAgentBase';
import {
  IRequirementsComplianceResult,
  ISolution,
  EvaluationDecision,
  IChallengeRequirement
} from '../../../models/interfaces';
import { logger } from '../../../utils/logger';
import { GitHubService, IRepositoryStructure } from '../../../services/github.service';
import { commonTechnologies } from '../../../constants/common.tech.things';

/**
 * Requirements Compliance Agent
 * Validates that GitHub submissions meet challenge requirements
 */
export class RequirementsComplianceAgent extends AIAgentBase<IRequirementsComplianceResult> {
  public name = 'RequirementsComplianceAgent';
  public description = 'Verifies challenge requirements adherence in GitHub submissions';

  /**
   * Evaluate a GitHub solution for requirements compliance
   * @param solution - The solution to evaluate
   * @returns Evaluation result with score and detailed feedback
   */
  public async evaluateInternal(solution: ISolution): Promise<IRequirementsComplianceResult> {
    try {
      // Get the challenge requirements
      const challenge = solution.challenge instanceof Object ? solution.challenge : null;
      if (!challenge) {
        logger.warn(`Challenge not found for solution in requirements check`, {
          solutionId: solution._id?.toString()
        });

        return this.createErrorResult(
          'Unable to verify requirements compliance due to missing challenge details.'
        );
      }

      // Extract GitHub repository information
      const repoInfo = await this.extractGitHubRepoInfo(solution.submissionUrl);

      logger.debug(`Analyzing repository structure for requirements compliance`, {
        solutionId: solution._id?.toString(),
        repository: `${repoInfo.owner}/${repoInfo.repo}`
      });

      // Analyze repository structure using GitHubService
      const repoStructure = await GitHubService.analyzeRepositoryStructure(repoInfo.owner, repoInfo.repo);

      // Extract requirements from the challenge
      const requirements = this.extractRequirementsFromChallenge(challenge);

      logger.debug(`Extracted ${requirements.length} requirements from challenge`, {
        solutionId: solution._id?.toString(),
        challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id
      });

      // Verify each requirement against the repository
      const requirementResults = await this.verifyRequirements(repoInfo, repoStructure, requirements);

      // Calculate scores and generate feedback
      const [score, feedback, metadata] = this.calculateScoresAndFeedback(
        requirementResults,
        repoStructure,
        solution.description || ''
      );

      logger.info(`Requirements compliance evaluation complete`, {
        solutionId: solution._id?.toString(),
        repository: `${repoInfo.owner}/${repoInfo.repo}`,
        score,
        requirementsMet: metadata.requirementsSatisfied,
        totalRequirements: metadata.totalRequirements
      });

      return {
        score,
        feedback,
        metadata,
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
   * Extract requirements from challenge
   * This would normally parse structured requirements from the challenge
   * @param challenge - The challenge object from the database
   * @returns List of requirements
   */
  private extractRequirementsFromChallenge(challenge: any): IChallengeRequirement[] {
    // In a production environment, this would parse requirements from a structured format
    // For example, the challenge might have a requirements array or a structured format

    const requirements: IChallengeRequirement[] = [];

    // Log that we're starting requirement extraction
    logger.debug(`Extracting requirements for challenge: ${challenge.title || 'Untitled Challenge'}`, {
      challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id
    });

    // If challenge has structured requirements field, use it
    if (challenge.requirements && Array.isArray(challenge.requirements)) {
      logger.debug(`Challenge has structured requirements (${challenge.requirements.length})`, {
        challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id
      });

      challenge.requirements.forEach((req: any, index: number) => {
        // Create requirement with all available fields from the structured data
        const requirement: IChallengeRequirement = {
          id: req.id || `req_${index}`,
          name: req.name || `Requirement ${index + 1}`,
          description: req.description || '',
          type: req.type || 'other',
          importance: req.importance || 'important'
        };

        // Add all other properties that exist on the requirement
        Object.keys(req).forEach(key => {
          if (key !== 'id' && key !== 'name' && key !== 'description' && key !== 'type' && key !== 'importance') {
            (requirement as any)[key] = req[key];
          }
        });

        requirements.push(requirement);

        logger.debug(`Added structured requirement: ${requirement.name}`, {
          requirementId: requirement.id,
          importance: requirement.importance,
          type: requirement.type
        });
      });

      // Even when structured requirements exist, still analyze description
      // for any additional implicit requirements that might be mentioned
      this.analyzeDescriptionForAdditionalRequirements(challenge.description || '', requirements);

      return requirements;
    }

    // Otherwise, need to thoroughly extract from challenge description
    logger.debug(`No structured requirements found. Analyzing challenge description.`, {
      challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id,
      descriptionLength: (challenge.description || '').length
    });

    const description = challenge.description || '';

    // Break down description into sections for better analysis
    const sections = this.splitDescriptionIntoSections(description);

    // Analyze each section of the description
    for (const section of sections) {
      this.analyzeDescriptionSection(section, requirements);
    }

    // Look for specific technology requirements
    const techRequirements = this.extractTechnologyRequirements(description);

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

    // Handle the case where no requirements could be extracted
    if (requirements.length === 0) {
      logger.warn(`No requirements extracted from challenge description. Using basic defaults.`, {
        challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id
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

    // Final logging of extracted requirements
    logger.info(`Extracted ${requirements.length} requirements for challenge`, {
      challengeId: typeof challenge._id === 'object' && challenge._id !== null ? challenge._id.toString() : challenge._id,
      requirementCount: requirements.length,
      criticalCount: requirements.filter(r => r.importance === 'critical').length
    });

    return requirements;
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
  private analyzeDescriptionSection(section: string, requirements: IChallengeRequirement[]): void {
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
      // Add code quality as an explicit requirement
      requirements.push({
        id: 'req_code_quality',
        name: 'Code Quality',
        description: 'Project must demonstrate good code quality and best practices',
        type: 'quality',
        importance: 'important'
      });
    }

    // Check for README/documentation requirements
    if (
      sectionLower.includes('readme') ||
      sectionLower.includes('documentation') ||
      sectionLower.includes('document your')
    ) {
      const existingReadmeReq = requirements.find(req =>
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
  private addRequirementFromText(text: string, idPrefix: string, requirements: IChallengeRequirement[]): void {
    const lowerText = text.toLowerCase();

    // Determine requirement importance
    const isCritical =
      lowerText.includes('must') ||
      lowerText.includes('required') ||
      lowerText.includes('essential') ||
      lowerText.includes('critical');

    const importance = isCritical ? 'critical' : 'important';

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
  private analyzeDescriptionForAdditionalRequirements(description: string, requirements: IChallengeRequirement[]): void {
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
    requirements: IChallengeRequirement[]
  ): Promise<Array<{
    requirement: IChallengeRequirement;
    satisfied: boolean;
    details: string;
  }>> {
    const results: Array<{
      requirement: IChallengeRequirement;
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
   * @returns Score, feedback, and metadata
   */
  private calculateScoresAndFeedback(
    requirementResults: Array<{
      requirement: IChallengeRequirement;
      satisfied: boolean;
      details: string;
    }>,
    structure: IRepositoryStructure,
    description: string
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
      const criticalPenalty =
        ((criticalRequirements.length - satisfiedCritical) / criticalRequirements.length) * 50;
      baseScore = Math.max(0, baseScore - criticalPenalty);
    }

    // Structure penalties
    const structurePenalty = !structure.hasProperStructure ? 10 : 0;
    const readmePenalty = !structure.hasReadme ? 10 : 0;

    // Description penalties
    const formatErrors: string[] = [];
    if (description.length < 50) {
      formatErrors.push('Solution description is too brief (less than 50 characters)');
    }

    const formatPenalty = formatErrors.length * 5;

    // Calculate final score
    const finalScore = Math.max(0, Math.min(100,
      baseScore - structurePenalty - readmePenalty - formatPenalty
    ));

    // Generate missing requirements list
    const missingRequirements = requirementResults
      .filter(r => !r.satisfied)
      .map(r => `${r.requirement.name} - ${r.details}`);

    // Generate appropriate feedback
    let feedback = '';
    if (finalScore > 80) {
      feedback = 'GitHub repository meets most requirements with minor issues.';
    } else if (finalScore > 50) {
      feedback = 'GitHub repository meets basic requirements but has significant gaps.';
    } else {
      feedback = 'GitHub repository fails to meet several key requirements.';
    }

    // Add details about missing requirements
    if (missingRequirements.length > 0) {
      feedback += ' Missing requirements: ' + missingRequirements.join('; ') + '.';
    }

    // Add details about repository structure
    if (!structure.hasProperStructure) {
      feedback += ' Repository structure does not follow required pattern.';
    }

    // Add details about format issues
    if (formatErrors.length > 0) {
      feedback += ' Format issues: ' + formatErrors.join('; ') + '.';
    }

    // Prepare metadata
    const metadata: IRequirementsComplianceResult['metadata'] = {
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
    };

    return [
      Math.round(finalScore), // Round to whole number
      feedback,
      metadata
    ];
  }

  /**
   * Override the default decision logic for requirements compliance
   * @param result - The evaluation result
   * @returns The decision to pass, fail, or request review
   */
  protected determineDecision(result: IRequirementsComplianceResult): EvaluationDecision {
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