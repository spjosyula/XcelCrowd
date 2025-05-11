import axios, { AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';
import { setTimeout as setTimeoutPromise } from 'timers/promises';

// Internal utilities
import { MongoSanitizer } from '../utils/mongo.sanitize';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../models/interfaces';
import { logger } from '../utils/logger';
import { githubTokenManager } from '../config/github.token.manager';

// Extend HTTP_STATUS with missing codes
enum EXTENDED_HTTP_STATUS {
  SERVICE_UNAVAILABLE = 503
}

// Common interfaces
export interface IGitHubOwner {
  login: string;
  type: string;
}

export interface IGitHubLicense {
  key: string;
  name: string;
  url: string;
}

export interface IGitHubRepoDetails {
  name: string;
  description: string;
  owner: IGitHubOwner;
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
  license?: IGitHubLicense;
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

// Cache entry types
interface CacheEntry<T> {
  timestamp: number;
  value: T;
}

interface RepoDetailsCacheEntry {
  timestamp: number;
  repoDetails?: IGitHubRepoDetails;
  exists: boolean;
  accessible: boolean;
  error?: string;
}

interface StructureCacheEntry {
  timestamp: number;
  structure: IRepositoryStructure;
}

interface ContentCacheEntry {
  timestamp: number;
  content: string;
}

interface ContentsCacheEntry {
  timestamp: number;
  contents: IGitHubRepoContent[];
}

interface RepoFilesCacheEntry {
  timestamp: number;
  files: Array<{ path: string; content: string }>;
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
    TIMEOUT_MS: 5000,
    MAX_FILE_SIZE_BYTES: 5 * 1024 * 1024, // 5MB
    MAX_TRAVERSAL_DEPTH: 10,
    MAX_ENTRIES_PER_CACHE: 1000,
    MAX_FILES_TO_ANALYZE: 100,
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY_BASE_MS: 1000,
    REQUEST_CONCURRENCY: 3
  };

  // Repository cache with LRU implementation
  private static repositoryCache = new Map<string, RepoDetailsCacheEntry>();
  private static repositoryCacheKeys: string[] = [];

  // Repository structure cache
  private static structureCache = new Map<string, StructureCacheEntry>();
  private static structureCacheKeys: string[] = [];

  // File content cache
  private static fileContentCache = new Map<string, ContentCacheEntry>();
  private static fileContentCacheKeys: string[] = [];

  // Repository contents cache
  private static contentsCache = new Map<string, ContentsCacheEntry>();
  private static contentsCacheKeys: string[] = [];

  // Repository files cache
  private static repoFilesCache = new Map<string, RepoFilesCacheEntry>();
  private static repoFilesCacheKeys: string[] = [];

  // Circuit breaker state
  private static circuitBreakerState = {
    isOpen: false,
    failureCount: 0,
    lastFailureTime: 0,
    resetThreshold: 5, // Number of failures before opening
    resetTimeout: 60 * 1000, // 1 minute timeout before trying again
  };

  // Common code file extensions for priority analysis
  private static readonly CODE_EXTENSIONS = [
    '.js', '.ts', '.jsx', '.tsx', '.py', '.java',
    '.c', '.cpp', '.h', '.hpp', '.go', '.rs',
    '.php', '.rb', '.cs', '.html', '.css', '.scss'
  ];

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
      // Prepare request headers
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Use common request method with retry logic
      const response = await this.makeApiRequest<IGitHubRepoDetails>(
        `https://api.github.com/repos/${owner}/${repo}`,
        { headers }
      );

      // Cache successful result
      const result = {
        timestamp: Date.now(),
        exists: true,
        accessible: true,
        repoDetails: response.data
      };

      this.addToRepositoryCache(cacheKey, result);

      return {
        exists: true,
        accessible: true,
        repoDetails: response.data
      };
    } catch (error) {
      // Handle 404 (repo doesn't exist) and 403 (no access)
      if (axios.isAxiosError(error) && error.response) {
        const exists = error.response.status !== 404;
        const accessible = false;

        // Cache the result
        const result = {
          timestamp: Date.now(),
          exists,
          accessible,
          error: error.message
        };

        this.addToRepositoryCache(cacheKey, result);

        return { exists, accessible };
      }

      // For other errors, log and return a safe result
      logger.error(`Error verifying GitHub repository`, {
        owner,
        repo,
        error: error instanceof Error ? error.message : String(error)
      });

      // Cache the error result
      const result = {
        timestamp: Date.now(),
        exists: false,
        accessible: false,
        error: error instanceof Error ? error.message : String(error)
      };

      this.addToRepositoryCache(cacheKey, result);

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

    try {
      // Get GitHub API token from token manager
      const token = githubTokenManager.getNextToken();

      // Prepare API request headers
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Use unified request method with retry logic
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
      const response = await this.makeApiRequest<IGitHubRepoContent | IGitHubRepoContent[]>(
        apiUrl,
        { headers }
      );

      // Process the response
      const contents = Array.isArray(response.data) ? response.data : [response.data];

      // Cache the contents
      this.addToContentsCache(cacheKey, {
        timestamp: Date.now(),
        contents
      });

      return contents;
    } catch (error) {
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

      // Use unified request method with retry logic
      const response = await this.makeApiRequest<{
        content?: string;
        encoding?: string;
        size?: number;
        name?: string;
      }>(apiUrl, { headers });

      // Check file size before decoding
      if (response.data.size && response.data.size > this.SECURITY_CONFIG.MAX_FILE_SIZE_BYTES) {
        throw new ApiError(
          HTTP_STATUS.UNPROCESSABLE_ENTITY,
          `File size exceeds the maximum allowed size (${this.SECURITY_CONFIG.MAX_FILE_SIZE_BYTES / 1024 / 1024}MB)`,
          true,
          'FILE_TOO_LARGE'
        );
      }

      // Decode content
      if (response.data && response.data.content) {
        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');

        // Cache the content
        this.addToContentCache(cacheKey, {
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
   * Analyze repository structure recursively with timeout
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

      // Set a timeout for the analysis (30 seconds)
      const analysisPromise = this.performRepositoryAnalysis(owner, repo, structure);
      const analysisWithTimeout = this.executeWithTimeout(
        analysisPromise,
        30000,
        'Repository analysis timed out'
      );

      // Execute with timeout
      await analysisWithTimeout;

      // Process the files to determine features
      structure.hasReadme = structure.files.some(file =>
        file.name.toLowerCase() === 'readme.md' ||
        file.name.toLowerCase() === 'readme.txt' ||
        file.name.toLowerCase() === 'readme'
      );

      // Check if structure is proper (basic requirements)
      structure.hasProperStructure = structure.hasReadme &&
        structure.files.length > 3 &&
        structure.packageFiles.length > 0;

      // Cache the result
      this.addToStructureCache(cacheKey, {
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
  * Helper method to execute a promise with a timeout
  * @param promise - The promise to execute
  * @param timeoutMs - Timeout in milliseconds
  * @param errorMessage - Error message if timeout occurs
  * @returns Promise result
  * @throws ApiError if timeout occurs
  */
  private static async executeWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorMessage: string
  ): Promise<T> {
    // Use Node.js standard setTimeout instead of the Promise-based version
    let timeoutHandle: NodeJS.Timeout | undefined = undefined;

    // Create a promise that rejects after the timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      // Use global setTimeout which returns NodeJS.Timeout
      timeoutHandle = global.setTimeout(() => {
        reject(new ApiError(
          HTTP_STATUS.GATEWAY_TIMEOUT,
          errorMessage,
          true,
          'OPERATION_TIMEOUT'
        ));
      }, timeoutMs);
    });

    try {
      // Race the original promise against the timeout
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      // Clear the timeout to prevent memory leaks
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  /**
   * Perform the actual repository analysis
   * @param owner - Repository owner
   * @param repo - Repository name 
   * @param structure - Structure object to update
   */
  private static async performRepositoryAnalysis(
    owner: string,
    repo: string,
    structure: IRepositoryStructure
  ): Promise<void> {
    // Get repository contents recursively
    await this.getRepositoryContentsRecursive(owner, repo, '', structure);

    // If README exists, get its content
    if (structure.files.some(file =>
      file.name.toLowerCase() === 'readme.md' ||
      file.name.toLowerCase() === 'readme.txt' ||
      file.name.toLowerCase() === 'readme'
    )) { 
      const readmeFile = structure.files.find(file =>
        file.name.toLowerCase() === 'readme.md' ||
        file.name.toLowerCase() === 'readme.txt' ||
        file.name.toLowerCase() === 'readme'
      );

      if (readmeFile) {
        try {
          structure.readmeContent = await this.getFileContent(
            owner,
            repo,
            readmeFile.path
          );
        } catch (error) {
          logger.warn(`Error fetching README content`, {
            path: readmeFile.path,
            error: error instanceof Error ? error.message : String(error)
          });
          // Don't fail the entire analysis if README fetching fails
        }
      }
    }

    // Process package files with error handling for each file
    for (const file of structure.files) {
      if (file.name === 'package.json') {
        await this.processPackageJson(owner, repo, file, structure);
      } else if (file.name === 'requirements.txt') {
        await this.processRequirementsTxt(owner, repo, file, structure);
      } else if (file.name === 'Gemfile') {
        await this.processGemfile(owner, repo, file, structure);
      }
    }
  }

  /**
   * Process package.json file
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param file - File information
   * @param structure - Structure object to update
   */
  private static async processPackageJson(
    owner: string,
    repo: string,
    file: IFileInfo,
    structure: IRepositoryStructure
  ): Promise<void> {
    try {
      const content = await this.getFileContent(owner, repo, file.path);

      // Validate content is valid JSON before parsing
      try {
        const packageJson = JSON.parse(content);

        structure.packageFiles.push({
          type: 'npm',
          path: file.path,
          dependencies: Object.keys(packageJson.dependencies || {}),
          devDependencies: Object.keys(packageJson.devDependencies || {})
        });
      } catch (parseError) {
        logger.warn(`Invalid JSON in package.json at ${file.path}`, {
          error: parseError instanceof Error ? parseError.message : String(parseError),
          repository: `${owner}/${repo}`
        });
      }
    } catch (error) {
      logger.warn(`Error fetching package.json content in ${file.path}`, {
        error: error instanceof Error ? error.message : String(error),
        repository: `${owner}/${repo}`
      });
    }
  }

  /**
   * Process requirements.txt file 
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param file - File information
   * @param structure - Structure object to update
   */
  private static async processRequirementsTxt(
    owner: string,
    repo: string,
    file: IFileInfo,
    structure: IRepositoryStructure
  ): Promise<void> {
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
      logger.warn(`Error processing requirements.txt in ${file.path}`, {
        error: error instanceof Error ? error.message : String(error),
        repository: `${owner}/${repo}`
      });
    }
  }

  /**
   * Process Gemfile
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param file - File information
   * @param structure - Structure object to update
   */
  private static async processGemfile(
    owner: string,
    repo: string,
    file: IFileInfo,
    structure: IRepositoryStructure
  ): Promise<void> {
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
      logger.warn(`Error processing Gemfile in ${file.path}`, {
        error: error instanceof Error ? error.message : String(error),
        repository: `${owner}/${repo}`
      });
    }
  }

  /**
   * Get repository contents recursively
   * @param owner - Repository owner
   * @param repo - Repository name
   * @param path - Current path within repository
   * @param structure - Structure object to update
   * @param depth - Current recursion depth
   */
  private static async getRepositoryContentsRecursive(
    owner: string,
    repo: string,
    path: string,
    structure: IRepositoryStructure,
    depth: number = 0
  ): Promise<void> {
    // Protect against excessive recursion
    if (depth >= this.SECURITY_CONFIG.MAX_TRAVERSAL_DEPTH) {
      logger.warn(`Maximum traversal depth reached for ${owner}/${repo} at path ${path}`);
      return;
    }

    // Protect against excessive files
    if (structure.files.length >= this.SECURITY_CONFIG.MAX_FILES_TO_ANALYZE) {
      logger.warn(`Maximum file count reached for ${owner}/${repo}`);
      return;
    }

    try {
      // Get contents at current path
      const contents = await this.getRepositoryContents(owner, repo, path);

      // Process each item
      for (const item of contents) {
        if (item.type === 'file') {
          // Skip files that are too large
          if (item.size > this.SECURITY_CONFIG.MAX_FILE_SIZE_BYTES) {
            logger.debug(`Skipping large file ${item.path} (${item.size} bytes)`);
            continue;
          }

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

          // Recursively process directory with increased depth
          await this.getRepositoryContentsRecursive(owner, repo, item.path, structure, depth + 1);

          // Avoid hitting rate limits
          await setTimeoutPromise(100);
        } else if (item.type === 'symlink' || item.type === 'submodule') {
          // Skip symlinks at depths > 0 to prevent cycles
          if (depth > 0 && item.type === 'symlink') {
            continue;
          }

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

    try {
      // Get GitHub API token from token manager
      const token = githubTokenManager.getNextToken();

      // Prepare API request
      const apiUrl = `https://api.github.com/repos/${owner}/${repo}/readme`;
      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github.v3.raw',
        'User-Agent': 'XcelCrowd-AI-Evaluation'
      };

      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Use unified request method with retry logic
      const response = await this.makeApiRequest<string>(
        apiUrl,
        {
          headers,
          responseType: 'text'
        }
      );

      // Store the content in cache
      const readmeContent = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);

      this.addToContentCache(cacheKey, {
        timestamp: Date.now(),
        content: readmeContent
      });

      return readmeContent;
    } catch (error) {
      // If README is not found, that's fine - it could just be missing
      if (axios.isAxiosError(error) && error.response && error.response.status === 404) {
        logger.debug(`README not found for ${owner}/${repo}`);

        // Cache empty result to avoid repeated requests
        this.addToContentCache(cacheKey, {
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
  ): Promise<Array<{ path: string; content: string }>> {
    // Enforce reasonable limits on maxFiles
    const limitedMaxFiles = Math.min(maxFiles, this.SECURITY_CONFIG.MAX_FILES_TO_ANALYZE);

    // Check cache first
    const cacheKey = `${owner}/${repo}/files/${limitedMaxFiles}`;
    const cachedFiles = this.repoFilesCache.get(cacheKey);

    if (cachedFiles && (Date.now() - cachedFiles.timestamp < this.CACHE_TTL)) {
      logger.debug(`Using cached repository files for ${cacheKey}`);
      return cachedFiles.files;
    }

    try {
      // Get repository contents first
      const contents = await this.getRepositoryContents(owner, repo);

      // Use predefined list of code file extensions
      const codeExtensions = this.CODE_EXTENSIONS;

      // Filter and prioritize code files
      const codeFiles = contents.filter(file => {
        if (file.type !== 'file') return false;
        if (file.size > this.SECURITY_CONFIG.MAX_FILE_SIZE_BYTES) return false;

        const ext = file.name.includes('.') ?
          `.${file.name.split('.').pop()?.toLowerCase()}` : '';
        return codeExtensions.includes(ext);
      });

      // Get a balanced sample - if we don't have enough code files, add other files
      let filesToAnalyze = [...codeFiles];

      if (filesToAnalyze.length < limitedMaxFiles) {
        const otherFiles = contents.filter(file =>
          file.type === 'file' &&
          file.size <= this.SECURITY_CONFIG.MAX_FILE_SIZE_BYTES &&
          !codeFiles.includes(file)
        );

        filesToAnalyze = [
          ...filesToAnalyze,
          ...otherFiles.slice(0, limitedMaxFiles - filesToAnalyze.length)
        ];
      }

      // Limit to max files
      filesToAnalyze = filesToAnalyze.slice(0, limitedMaxFiles);

      // Fetch content for each file with concurrency control
      const files: Array<{ path: string; content: string }> = [];

      // Process files in batches to control concurrency
      const batchSize = this.SECURITY_CONFIG.REQUEST_CONCURRENCY;

      for (let i = 0; i < filesToAnalyze.length; i += batchSize) {
        const batch = filesToAnalyze.slice(i, i + batchSize);
        const batchPromises = batch.map(async (file) => {
          try {
            const content = await this.getFileContent(owner, repo, file.path);
            return {
              path: file.path,
              content
            };
          } catch (error) {
            logger.debug(`Error fetching content for file ${file.path}`, {
              error: error instanceof Error ? error.message : String(error)
            });

            // Add file with empty content rather than failing
            return {
              path: file.path,
              content: ''
            };
          }
        });

        // Wait for batch to complete
        const batchResults = await Promise.all(batchPromises);
        files.push(...batchResults);

        // Add slight delay between batches
        if (i + batchSize < filesToAnalyze.length) {
          await setTimeoutPromise(200);
        }
      }

      // Cache the results
      this.addToRepoFilesCache(cacheKey, {
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

  /**
   * Add an entry to the repository cache with LRU eviction
   * @param key - Cache key
   * @param value - Value to cache
   */
  private static addToRepositoryCache(key: string, value: RepoDetailsCacheEntry): void {
    // If key already exists, remove it from the order tracking
    const existingIndex = this.repositoryCacheKeys.indexOf(key);
    if (existingIndex !== -1) {
      this.repositoryCacheKeys.splice(existingIndex, 1);
    }

    // Add/update the cache entry
    this.repositoryCache.set(key, value);
    this.repositoryCacheKeys.push(key);

    // Evict oldest entry if we exceed the size limit
    if (this.repositoryCacheKeys.length > this.SECURITY_CONFIG.MAX_ENTRIES_PER_CACHE) {
      const oldestKey = this.repositoryCacheKeys.shift();
      if (oldestKey) {
        this.repositoryCache.delete(oldestKey);
      }
    }
  }

  /**
   * Add an entry to the structure cache with LRU eviction
   * @param key - Cache key
   * @param value - Value to cache
   */
  private static addToStructureCache(key: string, value: StructureCacheEntry): void {
    const existingIndex = this.structureCacheKeys.indexOf(key);
    if (existingIndex !== -1) {
      this.structureCacheKeys.splice(existingIndex, 1);
    }

    this.structureCache.set(key, value);
    this.structureCacheKeys.push(key);

    if (this.structureCacheKeys.length > this.SECURITY_CONFIG.MAX_ENTRIES_PER_CACHE) {
      const oldestKey = this.structureCacheKeys.shift();
      if (oldestKey) {
        this.structureCache.delete(oldestKey);
      }
    }
  }

  /**
   * Add an entry to the file content cache with LRU eviction
   * @param key - Cache key
   * @param value - Value to cache
   */
  private static addToContentCache(key: string, value: ContentCacheEntry): void {
    const existingIndex = this.fileContentCacheKeys.indexOf(key);
    if (existingIndex !== -1) {
      this.fileContentCacheKeys.splice(existingIndex, 1);
    }

    this.fileContentCache.set(key, value);
    this.fileContentCacheKeys.push(key);

    if (this.fileContentCacheKeys.length > this.SECURITY_CONFIG.MAX_ENTRIES_PER_CACHE) {
      const oldestKey = this.fileContentCacheKeys.shift();
      if (oldestKey) {
        this.fileContentCache.delete(oldestKey);
      }
    }
  }

  /**
   * Add an entry to the repository contents cache with LRU eviction
   * @param key - Cache key
   * @param value - Value to cache
   */
  private static addToContentsCache(key: string, value: ContentsCacheEntry): void {
    const existingIndex = this.contentsCacheKeys.indexOf(key);
    if (existingIndex !== -1) {
      this.contentsCacheKeys.splice(existingIndex, 1);
    }

    this.contentsCache.set(key, value);
    this.contentsCacheKeys.push(key);

    if (this.contentsCacheKeys.length > this.SECURITY_CONFIG.MAX_ENTRIES_PER_CACHE) {
      const oldestKey = this.contentsCacheKeys.shift();
      if (oldestKey) {
        this.contentsCache.delete(oldestKey);
      }
    }
  }

  /**
   * Add an entry to the repository files cache with LRU eviction
   * @param key - Cache key
   * @param value - Value to cache
   */
  private static addToRepoFilesCache(key: string, value: RepoFilesCacheEntry): void {
    const existingIndex = this.repoFilesCacheKeys.indexOf(key);
    if (existingIndex !== -1) {
      this.repoFilesCacheKeys.splice(existingIndex, 1);
    }

    this.repoFilesCache.set(key, value);
    this.repoFilesCacheKeys.push(key);

    if (this.repoFilesCacheKeys.length > this.SECURITY_CONFIG.MAX_ENTRIES_PER_CACHE) {
      const oldestKey = this.repoFilesCacheKeys.shift();
      if (oldestKey) {
        this.repoFilesCache.delete(oldestKey);
      }
    }
  }

  /**
   * Updates the circuit breaker state based on API call outcomes
   * @param success - Whether the API call was successful
   */
  private static updateCircuitBreaker(success: boolean): void {
    if (success) {
      // Reset failure count on success
      this.circuitBreakerState.failureCount = 0;
      this.circuitBreakerState.isOpen = false;
    } else {
      // Increment failure count and potentially open circuit
      this.circuitBreakerState.failureCount++;
      this.circuitBreakerState.lastFailureTime = Date.now();

      if (this.circuitBreakerState.failureCount >= this.circuitBreakerState.resetThreshold) {
        this.circuitBreakerState.isOpen = true;
        logger.warn('Circuit breaker opened due to multiple GitHub API failures');
      }
    }
  }

  /**
   * Checks if circuit breaker is open, and if enough time has elapsed to try again
   * @returns Whether API calls should be attempted
   */
  private static canMakeApiCall(): boolean {
    if (!this.circuitBreakerState.isOpen) {
      return true;
    }

    // Check if enough time has passed to try again
    const timeSinceFailure = Date.now() - this.circuitBreakerState.lastFailureTime;
    if (timeSinceFailure >= this.circuitBreakerState.resetTimeout) {
      logger.info('Circuit breaker reset timeout elapsed, attempting API call');
      return true;
    }

    return false;
  }

  /**
   * Makes a GitHub API request with retry logic and circuit breaker
   * @param url - API URL to call
   * @param options - Request options
   * @returns Axios response
   * @throws ApiError if the request fails after retries
   */
  private static async makeApiRequest<T>(
    url: string,
    options: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    // Check circuit breaker
    if (!this.canMakeApiCall()) {
      throw new ApiError(
        EXTENDED_HTTP_STATUS.SERVICE_UNAVAILABLE,
        'GitHub API service is currently unavailable, please try again later',
        true,
        'GITHUB_API_UNAVAILABLE'
      );
    }

    let lastError: Error | undefined;

    // Apply default options
    const requestOptions: AxiosRequestConfig = {
      timeout: this.SECURITY_CONFIG.TIMEOUT_MS,
      maxRedirects: this.SECURITY_CONFIG.MAX_REDIRECT_COUNT,
      ...options
    };

    // Try request with retries
    for (let attempt = 0; attempt < this.SECURITY_CONFIG.RETRY_ATTEMPTS; attempt++) {
      try {
        const response = await axios.request<T>({
          url,
          ...requestOptions
        });

        // Update circuit breaker on success
        this.updateCircuitBreaker(true);

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
        const token = requestOptions.headers?.['Authorization'] as string | undefined;
        if (token && token.startsWith('Bearer ')) {
          const actualToken = token.substring(7);
          githubTokenManager.updateTokenMetrics(
            actualToken,
            true,
            rateLimitRemaining,
            rateLimitReset
          );
        }

        return response;
      } catch (error) {
        lastError = error as Error;

        // Update token metrics if token was used
        const token = requestOptions.headers?.['Authorization'] as string | undefined;
        if (token && token.startsWith('Bearer ')) {
          const actualToken = token.substring(7);
          githubTokenManager.updateTokenMetrics(actualToken, false);
        }

        // Handle specific error cases
        if (axios.isAxiosError(error)) {
          // If we get a 404 or other specific status, no need to retry
          if (error.response && (error.response.status === 404 || error.response.status === 403)) {
            this.updateCircuitBreaker(false);
            throw error;
          }

          // If we hit rate limits, wait longer before retrying
          if (error.response && error.response.status === 429) {
            // Extract rate limit reset time if available
            const resetHeader = error.response.headers['x-ratelimit-reset'];
            const resetTime = resetHeader ? parseInt(resetHeader, 10) * 1000 : null;

            // Calculate wait time - either until reset or use exponential backoff
            const waitTime = resetTime
              ? Math.max(0, resetTime - Date.now()) + 1000 // Add 1 second buffer
              : Math.pow(2, attempt) * this.SECURITY_CONFIG.RETRY_DELAY_BASE_MS;

            logger.warn(`Rate limited by GitHub API, waiting ${waitTime}ms before retry`, {
              attempt: attempt + 1,
              maxAttempts: this.SECURITY_CONFIG.RETRY_ATTEMPTS
            });

            await setTimeoutPromise(waitTime);
            continue;
          }
        }

        // For other errors, use exponential backoff
        const backoffTime = Math.pow(2, attempt) * this.SECURITY_CONFIG.RETRY_DELAY_BASE_MS;
        logger.debug(`GitHub API request failed, retrying in ${backoffTime}ms`, {
          attempt: attempt + 1,
          maxAttempts: this.SECURITY_CONFIG.RETRY_ATTEMPTS,
          url,
          error: error instanceof Error ? error.message : String(error)
        });

        await setTimeoutPromise(backoffTime);
      }
    }

    // If we get here, all retries failed
    this.updateCircuitBreaker(false);

    // Throw appropriate error
    if (axios.isAxiosError(lastError) && lastError.response) {
      // For known error responses, format appropriately
      if (lastError.response.status === 404) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'GitHub resource not found',
          true,
          'GITHUB_RESOURCE_NOT_FOUND'
        );
      } else if (lastError.response.status === 403 || lastError.response.status === 401) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'Access to GitHub resource forbidden',
          true,
          'GITHUB_ACCESS_FORBIDDEN'
        );
      } else if (lastError.response.status === 429) {
        throw new ApiError(
          HTTP_STATUS.TOO_MANY_REQUESTS,
          'GitHub API rate limit exceeded',
          true,
          'GITHUB_RATE_LIMIT_EXCEEDED'
        );
      }
    }

    // Generic error for other cases
    throw new ApiError(
      EXTENDED_HTTP_STATUS.SERVICE_UNAVAILABLE,
      'GitHub API request failed after multiple retries',
      true,
      'GITHUB_API_FAILURE'
    );
  }
}