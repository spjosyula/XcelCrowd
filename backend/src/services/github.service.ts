import { MongoSanitizer } from '../utils/mongo.sanitize';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../models/interfaces';
import { logger } from '../utils/logger';
import axios from 'axios';
import { githubTokenManager } from '../config/github.token.manager';
import { setTimeout } from 'timers/promises';

// Common interfaces
export interface IGitHubRepoDetails {
  name: string;
  description: string;
  owner: {
    login: string;
    type: string;
  };
  private: boolean;
  fork: boolean;
  created_at: string;
  updated_at: string;
  pushed_at: string;
  size: number;
  stargazers_count: number;
  watchers_count: number;
  forks_count: number;
  open_issues_count: number;
  default_branch: string;
  topics: string[];
  has_issues: boolean;
  has_projects: boolean;
  has_wiki: boolean;
  has_downloads: boolean;
  archived: boolean;
  disabled: boolean;
  license?: {
    key: string;
    name: string;
    url: string;
  };
}

export interface IGitHubRepoContent {
  type: string;
  name: string;
  path: string;
  sha: string;
  size: number;
  url: string;
  html_url: string;
  git_url: string;
  download_url: string | null;
}

export interface IRepositoryStructure {
  hasRequiredFiles: boolean;
  missingFiles: string[];
  hasReadme: boolean;
  hasProperStructure: boolean;
  fileExtensions: Set<string>;
  files: IFileInfo[];
  directories: string[];
  totalSize: number;
  readmeContent?: string;
  packageFiles: IPackageFile[];
}

export interface IFileInfo {
  path: string;
  name: string;
  extension: string;
  size: number;
  url: string;
  type: 'file' | 'dir' | 'symlink' | 'submodule';
}

export interface IPackageFile {
  type: 'npm' | 'python' | 'ruby' | 'other';
  path: string;
  dependencies: string[];
  devDependencies?: string[];
}

/**
 * Enterprise-grade GitHub service with robust security validation and caching
 * Provides utilities for GitHub repository operations
 */
export class GitHubService {
  // Allowed GitHub domains whitelist
  private static readonly ALLOWED_GITHUB_DOMAINS = ['github.com', 'www.github.com'];
  
  // Cache TTL - 30 minutes
  private static readonly CACHE_TTL = 30 * 60 * 1000;
  
  // Security configurations
  private static readonly SECURITY_CONFIG = {
    MAX_REDIRECT_COUNT: 3,
    TIMEOUT_MS: 5000
  };
  
  // Repository cache
  private static repositoryCache: Map<string, {
    timestamp: number;
    repoDetails?: IGitHubRepoDetails;
    exists: boolean;
    accessible: boolean;
    error?: string;
  }> = new Map();
  
  // Repository structure cache
  private static structureCache: Map<string, {
    timestamp: number;
    structure: IRepositoryStructure;
  }> = new Map();
  
  // File content cache
  private static fileContentCache: Map<string, {
    timestamp: number;
    content: string;
  }> = new Map();
  
  // Repository contents cache
  private static contentsCache: Map<string, {
    timestamp: number;
    contents: IGitHubRepoContent[];
  }> = new Map();
  
  // Repository files cache
  private static repoFilesCache: Map<string, {
    timestamp: number;
    files: Array<{path: string; content: string}>;
  }> = new Map();

  /**
   * Extract and validate GitHub repository information from URL
   * @param submissionUrl - The URL submitted by the user
   * @returns Object containing repository information
   * @throws ApiError with appropriate status if validation fails
   */
  public static extractGitHubRepoInfo(submissionUrl: string): {
    owner: string;
    repo: string;
    url: string
  } {
    const sanitizedUrl = MongoSanitizer.sanitizeGitHubUrl(submissionUrl);

    if (!sanitizedUrl) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Invalid GitHub repository URL',
        true,
        'INVALID_GITHUB_URL'
      );
    }

    try {
      const url = new URL(sanitizedUrl);

      // Validate GitHub domain against strict whitelist
      if (!this.ALLOWED_GITHUB_DOMAINS.includes(url.hostname.toLowerCase())) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'URL must be from github.com domain',
          true,
          'INVALID_GITHUB_DOMAIN'
        );
      }

      // Extract and validate path components
      const pathParts = url.pathname.split('/').filter(part => part.length > 0);

      // Ensure we have at least owner and repo parts
      if (pathParts.length < 2) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid GitHub repository URL format',
          true,
          'INVALID_REPO_URL_FORMAT'
        );
      }

      // Validate username and repo against GitHub naming rules
      const owner = pathParts[0];
      const repo = pathParts[1];

      // GitHub naming validation
      const githubNamePattern = /^[a-zA-Z0-9][\w.-]*$/;
      if (!githubNamePattern.test(owner)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid GitHub username format',
          true,
          'INVALID_GITHUB_USERNAME'
        );
      }

      if (!githubNamePattern.test(repo)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Invalid GitHub repository name format',
          true,
          'INVALID_GITHUB_REPO_NAME'
        );
      }

      // Security check: limit component lengths to prevent buffer attacks
      if (owner.length > 39) { // GitHub's max username length
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'GitHub username exceeds maximum length',
          true,
          'USERNAME_TOO_LONG'
        );
      }

      if (repo.length > 100) { // GitHub's max repo name length
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'GitHub repository name exceeds maximum length',
          true,
          'REPO_NAME_TOO_LONG'
        );
      }

      // Return normalized information with secure URL construction
      return {
        owner,
        repo,
        url: `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`
      };
    } catch (error) {
      // Enhanced error logging
      logger.error(`Error extracting GitHub repo information`, {
        submissionUrl,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });

      // Pass through ApiErrors, convert others to API errors
      if (error instanceof ApiError) {
        throw error;
      }

      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Invalid GitHub repository URL: ${error instanceof Error ? error.message : 'parsing error'}`,
        true,
        'INVALID_GITHUB_URL'
      );
    }
  }

  /**
   * Verify if a GitHub repository exists and is accessible
   * @param owner - The repository owner/username
   * @param repo - The repository name
   * @returns Object with exists, accessible flags, and repository details if available
   */
  public static async verifyGitHubRepository(
    owner: string,
    repo: string
  ): Promise<{ exists: boolean, accessible: boolean, repoDetails?: IGitHubRepoDetails }> {
    // Check cache first
    const cacheKey = `${owner}/${repo}`;
    const cachedResult = this.repositoryCache.get(cacheKey);

    if (cachedResult && (Date.now() - cachedResult.timestamp < this.CACHE_TTL)) {
      logger.debug(`Using cached repository verification result for ${cacheKey}`);
      return {
        exists: cachedResult.exists,
        accessible: cachedResult.accessible,
        repoDetails: cachedResult.repoDetails
      };
    }

    // Get GitHub API token from token manager
    const token = githubTokenManager.getNextToken();

    try {
      // Use GitHub API to check repository
      const response = await axios.get<IGitHubRepoDetails>(
        `https://api.github.com/repos/${owner}/${repo}`,
        {
          timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
          maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT,
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'XcelCrowd-AI-Evaluation',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
          }
        }
      );

      // Extract rate limit information from response headers
      let rateLimitRemaining: number | undefined;
      let rateLimitReset: number | undefined;

      if (response.headers && response.headers['x-ratelimit-remaining']) {
        rateLimitRemaining = parseInt(response.headers['x-ratelimit-remaining'], 10);
      }

      if (response.headers && response.headers['x-ratelimit-reset']) {
        rateLimitReset = parseInt(response.headers['x-ratelimit-reset'], 10);
      }

      // Update token metrics if token was used
      if (token) {
        githubTokenManager.updateTokenMetrics(
          token,
          true,
          rateLimitRemaining,
          rateLimitReset
        );
      }

      // Cache the result
      this.repositoryCache.set(cacheKey, {
        timestamp: Date.now(),
        exists: true,
        accessible: true,
        repoDetails: response.data
      });

      return {
        exists: true,
        accessible: true,
        repoDetails: response.data
      };
    } catch (error) {
      // Handle error and update token metrics if needed
      if (token) {
        githubTokenManager.updateTokenMetrics(token, false);
      }

      if (axios.isAxiosError(error) && error.response) {
        // 404 means repo doesn't exist, 403 means no access
        const exists = error.response.status !== 404;
        const accessible = false;

        // Cache the result
        this.repositoryCache.set(cacheKey, {
          timestamp: Date.now(),
          exists,
          accessible,
          error: error.message
        });

        return { exists, accessible };
      }

      // Network error or other problem
      logger.error(`Error verifying GitHub repository`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });

      // Cache the error result
      this.repositoryCache.set(cacheKey, {
        timestamp: Date.now(),
        exists: false,
        accessible: false,
        error: error instanceof Error ? error.message : String(error)
      });

      // Default to assuming it might exist but is inaccessible
      return {
        exists: false,
        accessible: false
      };
    }
  }

  /**
   * Get repository contents at a specific path
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param path - Path within repository
   * @returns Repository contents
   */
  public static async getRepositoryContents(
    owner: string,
    repo: string,
    path: string = ''
  ): Promise<IGitHubRepoContent[]> {
    // Check cache first
    const cacheKey = `${owner}/${repo}/contents/${path}`;
    const cachedContents = this.contentsCache.get(cacheKey);

    if (cachedContents && (Date.now() - cachedContents.timestamp < this.CACHE_TTL)) {
      logger.debug(`Using cached repository contents for ${cacheKey}`);
      return cachedContents.contents;
    }

    // Get GitHub API token from token manager
    const token = githubTokenManager.getNextToken();

    try {
      // Prepare API request
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Make the request
      const response = await axios.get(apiUrl, { 
        headers,
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });

      // Extract rate limit info
      let rateLimitRemaining: number | undefined;
      let rateLimitReset: number | undefined;

      if (response.headers && response.headers['x-ratelimit-remaining']) {
        rateLimitRemaining = parseInt(response.headers['x-ratelimit-remaining'], 10);
      }

      if (response.headers && response.headers['x-ratelimit-reset']) {
        rateLimitReset = parseInt(response.headers['x-ratelimit-reset'], 10);
      }

      // Update token metrics
      if (token) {
        githubTokenManager.updateTokenMetrics(
          token,
          true,
          rateLimitRemaining,
          rateLimitReset
        );
      }

      // Process the response
      const contents = Array.isArray(response.data) ? response.data : [response.data];

      // Cache the contents
      this.contentsCache.set(cacheKey, {
        timestamp: Date.now(),
        contents
      });

      return contents;
    } catch (error) {
      // Handle error and update token metrics if needed
      if (token) {
        githubTokenManager.updateTokenMetrics(token, false);
      }

      if (axios.isAxiosError(error) && error.response && error.response.status === 404) {
        logger.debug(`Path not found in repository: ${path}`, {
          owner,
          repo
        });
        return [];
      }

      logger.error(`Error fetching repository contents`, {
        owner,
        repo,
        path,
        error: error instanceof Error ? error.message : String(error)
      });

      throw error;
    }
  }

  /**
   * Get file content from GitHub repository
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param filePath - Path to the file
   * @returns File content as string
   */
  public static async getFileContent(
    owner: string,
    repo: string,
    filePath: string
  ): Promise<string> {
    const cacheKey = `${owner}/${repo}/${filePath}`;

    // Check cache first
    const cachedContent = this.fileContentCache.get(cacheKey);
    if (cachedContent && (Date.now() - cachedContent.timestamp) < this.CACHE_TTL) {
      return cachedContent.content;
    }

    try {
      // Get GitHub API token
      const token = githubTokenManager.getNextToken();

      // Prepare API request
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Make the request
      const response = await axios.get(apiUrl, { 
        headers,
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });

      // Update token metrics if available
      if (token && response.headers) {
        let rateLimitRemaining: number | undefined;
        let rateLimitReset: number | undefined;

        if (response.headers['x-ratelimit-remaining']) {
          rateLimitRemaining = parseInt(response.headers['x-ratelimit-remaining'], 10);
        }

        if (response.headers['x-ratelimit-reset']) {
          rateLimitReset = parseInt(response.headers['x-ratelimit-reset'], 10);
        }

        githubTokenManager.updateTokenMetrics(
          token,
          true,
          rateLimitRemaining,
          rateLimitReset
        );
      }

      // Decode content
      if (response.data && response.data.content) {
        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');

        // Cache the content
        this.fileContentCache.set(cacheKey, {
          timestamp: Date.now(),
          content
        });

        return content;
      }

      throw new Error('File content not available');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error fetching file content`, {
        owner,
        repo,
        filePath,
        error: errorMessage
      });

      throw error;
    }
  }

  /**
   * Analyze repository structure recursively
   * @param owner - Repository owner
   * @param repo - Repository name
   * @returns Repository structure analysis
   */
  public static async analyzeRepositoryStructure(
    owner: string,
    repo: string
  ): Promise<IRepositoryStructure> {
    const cacheKey = `${owner}/${repo}`;

    // Check cache first
    const cachedData = this.structureCache.get(cacheKey);
    if (cachedData && (Date.now() - cachedData.timestamp) < this.CACHE_TTL) {
      logger.debug(`Using cached repository structure for ${cacheKey}`);
      return cachedData.structure;
    }

    try {
      logger.debug(`Fetching repository structure for ${cacheKey}`);

      // Initialize structure
      const structure: IRepositoryStructure = {
        hasRequiredFiles: false,
        missingFiles: [],
        hasReadme: false,
        hasProperStructure: false,
        fileExtensions: new Set<string>(),
        files: [],
        directories: [],
        totalSize: 0,
        packageFiles: []
      };

      // Get repository contents recursively
      await this.getRepositoryContentsRecursive(owner, repo, '', structure);

      // Process the files to determine features
      structure.hasReadme = structure.files.some(file =>
        file.name.toLowerCase() === 'readme.md' ||
        file.name.toLowerCase() === 'readme.txt' ||
        file.name.toLowerCase() === 'readme'
      );

      // If README exists, get its content
      if (structure.hasReadme) {
        const readmeFile = structure.files.find(file =>
          file.name.toLowerCase() === 'readme.md' ||
          file.name.toLowerCase() === 'readme.txt' ||
          file.name.toLowerCase() === 'readme'
        );

        if (readmeFile) {
          structure.readmeContent = await this.getFileContent(
            owner,
            repo,
            readmeFile.path
          );
        }
      }

      // Process package files
      for (const file of structure.files) {
        if (file.name === 'package.json') {
          try {
            const content = await this.getFileContent(owner, repo, file.path);
            const packageJson = JSON.parse(content);

            structure.packageFiles.push({
              type: 'npm',
              path: file.path,
              dependencies: Object.keys(packageJson.dependencies || {}),
              devDependencies: Object.keys(packageJson.devDependencies || {})
            });
          } catch (error) {
            logger.warn(`Error parsing package.json in ${file.path}`, {
              error: error instanceof Error ? error.message : String(error),
              repository: cacheKey
            });
          }
        } else if (file.name === 'requirements.txt') {
          try {
            const content = await this.getFileContent(owner, repo, file.path);
            const dependencies = content
              .split('\n')
              .map(line => line.trim())
              .filter(line => line && !line.startsWith('#'))
              .map(line => {
                // Handle version specifiers
                const parts = line.split('==');
                return parts[0].trim();
              });

            structure.packageFiles.push({
              type: 'python',
              path: file.path,
              dependencies
            });
          } catch (error) {
            logger.warn(`Error parsing requirements.txt in ${file.path}`, {
              error: error instanceof Error ? error.message : String(error),
              repository: cacheKey
            });
          }
        } else if (file.name === 'Gemfile') {
          try {
            const content = await this.getFileContent(owner, repo, file.path);
            const dependencies = content
              .split('\n')
              .map(line => line.trim())
              .filter(line => line.startsWith('gem '))
              .map(line => {
                // Extract gem name
                const match = line.match(/gem\s+['"]([^'"]+)['"]/);
                return match ? match[1] : line;
              });

            structure.packageFiles.push({
              type: 'ruby',
              path: file.path,
              dependencies
            });
          } catch (error) {
            logger.warn(`Error parsing Gemfile in ${file.path}`, {
              error: error instanceof Error ? error.message : String(error),
              repository: cacheKey
            });
          }
        }
      }

      // Check if structure is proper (basic requirements)
      structure.hasProperStructure = structure.hasReadme &&
        structure.files.length > 3 &&
        structure.packageFiles.length > 0;

      // Cache the result
      this.structureCache.set(cacheKey, {
        timestamp: Date.now(),
        structure
      });

      return structure;
    } catch (error) {
      logger.error(`Error analyzing repository structure`, {
        repoOwner: owner,
        repoName: repo,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });

      throw error;
    }
  }

  /**
   * Get repository contents recursively
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param path - Current path within repository
   * @param structure - Structure object to update
   */
  private static async getRepositoryContentsRecursive(
    owner: string,
    repo: string,
    path: string,
    structure: IRepositoryStructure
  ): Promise<void> {
    try {
      // Get contents at current path
      const contents = await this.getRepositoryContents(owner, repo, path);

      // Process each item
      for (const item of contents) {
        if (item.type === 'file') {
          // Add file info
          const extension = (() => {
            const idx = item.name.lastIndexOf('.');
            return idx !== -1 ? item.name.substring(idx).toLowerCase() : '';
          })();
          structure.fileExtensions.add(extension);

          const fileInfo: IFileInfo = {
            path: item.path,
            name: item.name,
            extension,
            size: item.size,
            url: item.html_url,
            type: 'file'
          };

          structure.files.push(fileInfo);
          structure.totalSize += item.size;
        } else if (item.type === 'dir') {
          // Add directory
          structure.directories.push(item.path);

          // Recursively process directory
          await this.getRepositoryContentsRecursive(owner, repo, item.path, structure);

          // Avoid hitting rate limits
          await setTimeout(100);
        } else if (item.type === 'symlink' || item.type === 'submodule') {
          // Add with special type
          const fileInfo: IFileInfo = {
            path: item.path,
            name: item.name,
            extension: '',
            size: 0,
            url: item.html_url,
            type: item.type as 'symlink' | 'submodule'
          };

          structure.files.push(fileInfo);
        }
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response && error.response.status === 404) {
        logger.debug(`Path not found in repository: ${path}`, {
          owner,
          repo
        });
        // This is not a critical error, just means the path doesn't exist
        return;
      }

      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Error fetching repository contents recursively`, {
        owner,
        repo,
        path,
        error: errorMessage
      });

      throw error;
    }
  }

  /**
   * Get repository statistics (commits, contributors, branches)
   * @param owner - Repository owner
   * @param repo - Repository name
   * @returns Repository statistics
   */
  public static async getRepositoryStats(
    owner: string,
    repo: string
  ): Promise<{
    commitCount: number;
    contributorCount: number;
    branchCount: number;
  }> {
    try {
      // Get GitHub API token
      const token = githubTokenManager.getNextToken();

      // Prepare API request headers
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Get commit count (limited to 100 for performance)
      const commitsUrl = `https://api.github.com/repos/${owner}/${repo}/commits?per_page=100`;
      const commitsResponse = await axios.get(commitsUrl, { 
        headers, 
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });

      let commitCount = 0;
      if (Array.isArray(commitsResponse.data)) {
        commitCount = commitsResponse.data.length;
      }

      // Get contributors count
      const contributorsUrl = `https://api.github.com/repos/${owner}/${repo}/contributors?per_page=100`;
      const contributorsResponse = await axios.get(contributorsUrl, { 
        headers, 
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });

      let contributorCount = 0;
      if (Array.isArray(contributorsResponse.data)) {
        contributorCount = contributorsResponse.data.length;
      }

      // Get branches count
      const branchesUrl = `https://api.github.com/repos/${owner}/${repo}/branches?per_page=100`;
      const branchesResponse = await axios.get(branchesUrl, { 
        headers, 
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });

      let branchCount = 0;
      if (Array.isArray(branchesResponse.data)) {
        branchCount = branchesResponse.data.length;
      }

      // Update token metrics if provided
      if (token) {
        let rateLimitRemaining: number | undefined;
        let rateLimitReset: number | undefined;

        const lastResponse = branchesResponse;

        if (lastResponse.headers && lastResponse.headers['x-ratelimit-remaining']) {
          rateLimitRemaining = parseInt(lastResponse.headers['x-ratelimit-remaining'], 10);
        }

        if (lastResponse.headers && lastResponse.headers['x-ratelimit-reset']) {
          rateLimitReset = parseInt(lastResponse.headers['x-ratelimit-reset'], 10);
        }

        githubTokenManager.updateTokenMetrics(
          token,
          true,
          rateLimitRemaining,
          rateLimitReset
        );
      }

      return {
        commitCount,
        contributorCount,
        branchCount
      };
    } catch (error) {
      // Log but don't fail - stats are non-critical
      logger.warn(`Error fetching repository stats`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });

      // Default values
      return {
        commitCount: 1,
        contributorCount: 1,
        branchCount: 1
      };
    }
  }

  /**
   * Clear cache entries for a specific repository
   * @param owner - Repository owner
   * @param repo - Repository name
   */
  public static clearRepoCache(owner: string, repo: string): void {
    const cacheKey = `${owner}/${repo}`;
    
    // Clear all cache entries related to this repo
    this.repositoryCache.delete(cacheKey);
    this.structureCache.delete(cacheKey);
    
    // Clear file content cache entries
    for (const key of this.fileContentCache.keys()) {
      if (key.startsWith(cacheKey)) {
        this.fileContentCache.delete(key);
      }
    }
    
    // Clear contents cache entries
    for (const key of this.contentsCache.keys()) {
      if (key.startsWith(cacheKey)) {
        this.contentsCache.delete(key);
      }
    }
    
    logger.debug(`Cleared cache for repository ${cacheKey}`);
  }

  /**
   * Get README content from a GitHub repository
   * @param owner - Repository owner
   * @param repo - Repository name
   * @returns README file content as string
   */
  public static async getReadmeContent(
    owner: string,
    repo: string
  ): Promise<string> {
    // Check cache first
    const cacheKey = `${owner}/${repo}/readme`;
    const cachedContent = this.fileContentCache.get(cacheKey);
    
    if (cachedContent && (Date.now() - cachedContent.timestamp < this.CACHE_TTL)) {
      logger.debug(`Using cached README content for ${cacheKey}`);
      return cachedContent.content;
    }
    
    // Get GitHub API token from token manager
    const token = githubTokenManager.getNextToken();
    
    try {
      // Prepare API request
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/readme`;
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3.raw',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      // Make the request
      const response = await axios.get(apiUrl, {
        headers,
        timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
        maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT
      });
      
      // Extract rate limit info
      let rateLimitRemaining: number | undefined;
      let rateLimitReset: number | undefined;
      
      if (response.headers && response.headers['x-ratelimit-remaining']) {
        rateLimitRemaining = parseInt(response.headers['x-ratelimit-remaining'], 10);
      }
      
      if (response.headers && response.headers['x-ratelimit-reset']) {
        rateLimitReset = parseInt(response.headers['x-ratelimit-reset'], 10);
      }
      
      // Update token metrics
      if (token) {
        githubTokenManager.updateTokenMetrics(
          token,
          true,
          rateLimitRemaining,
          rateLimitReset
        );
      }
      
      // Store the content in cache
      const readmeContent = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
      this.fileContentCache.set(cacheKey, {
        timestamp: Date.now(),
        content: readmeContent
      });
      
      return readmeContent;
    } catch (error) {
      // If README is not found, that's fine - it could just be missing
      if (axios.isAxiosError(error) && error.response && error.response.status === 404) {
        logger.debug(`README not found for ${owner}/${repo}`);
        
        // Cache empty result to avoid repeated requests
        this.fileContentCache.set(cacheKey, {
          timestamp: Date.now(),
          content: ''
        });
        
        return '';
      }
      
      // Handle other errors
      logger.warn(`Error fetching README from GitHub repository`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Update token metrics if token was used
      if (token) {
        githubTokenManager.updateTokenMetrics(token, false);
      }
      
      // Return empty string rather than failing
      return '';
    }
  }
  
  /**
   * Get a sampling of repository files for analysis
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param maxFiles - Maximum number of files to retrieve
   * @returns Array of files with their content
   */
  public static async getRepositoryFiles(
    owner: string,
    repo: string,
    maxFiles: number = 5
  ): Promise<Array<{path: string; content: string}>> {
    // Check cache first
    const cacheKey = `${owner}/${repo}/files/${maxFiles}`;
    const cachedFiles = this.repoFilesCache.get(cacheKey);
    
    if (cachedFiles && (Date.now() - cachedFiles.timestamp < this.CACHE_TTL)) {
      logger.debug(`Using cached repository files for ${cacheKey}`);
      return cachedFiles.files;
    }
    
    try {
      // Get repository contents first
      const contents = await this.getRepositoryContents(owner, repo);
      
      // Focus on code files for analysis
      const codeExtensions = ['.js', '.ts', '.py', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb', '.cs', '.html', '.css'];
      
      // Filter and prioritize code files
      const codeFiles = contents.filter(file => {
        if (file.type !== 'file') return false;
        const ext = file.name.includes('.') ? `.${file.name.split('.').pop()?.toLowerCase()}` : '';
        return codeExtensions.includes(ext);
      });
      
      // Get a balanced sample - if we don't have enough code files, add other files
      let filesToAnalyze = [...codeFiles];
      
      if (filesToAnalyze.length < maxFiles) {
        const otherFiles = contents.filter(file => 
          file.type === 'file' && !codeFiles.includes(file)
        );
        
        filesToAnalyze = [...filesToAnalyze, ...otherFiles.slice(0, maxFiles - filesToAnalyze.length)];
      }
      
      // Limit to max files
      filesToAnalyze = filesToAnalyze.slice(0, maxFiles);
      
      // Fetch content for each file
      const files: Array<{path: string; content: string}> = [];
      
      for (const file of filesToAnalyze) {
        try {
          const content = await this.getFileContent(owner, repo, file.path);
          files.push({
            path: file.path,
            content
          });
        } catch (error) {
          logger.debug(`Error fetching content for file ${file.path}`, {
            error: error instanceof Error ? error.message : String(error)
          });
          
          // Add file with empty content rather than failing
          files.push({
            path: file.path,
            content: ''
          });
        }
        
        // Add slight delay between requests to respect rate limits
        await setTimeout(100);
      }
      
      // Cache the results
      this.repoFilesCache.set(cacheKey, {
        timestamp: Date.now(),
        files
      });
      
      return files;
    } catch (error) {
      logger.warn(`Error fetching repository files`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Return empty array rather than failing
      return [];
    }
  }
}