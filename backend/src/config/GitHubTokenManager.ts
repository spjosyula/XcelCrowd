import { logger } from '../utils/logger';
import axios from 'axios';
import { setTimeout } from 'timers/promises';
import fs from 'fs';
import path from 'path';

/**
 * Interface for token usage metrics
 */
interface ITokenMetrics {
  token: string;
  remaining: number;
  resetAt: number;
  lastUsed: number;
  consecutiveErrors: number;
  isActive: boolean;
  errorType?: string; // Track specific error types
}

/**
 * Rate limit information returned by GitHub API
 */
interface IGitHubRateLimit {
  limit: number;
  remaining: number;
  reset: number;
  used: number;
}

/**
 * Enterprise-grade GitHub token manager with token rotation and rate limit tracking
 * Implements token rotation strategies for optimal API usage
 */
export class GitHubTokenManager {
  private static instance: GitHubTokenManager;
  private tokens: ITokenMetrics[] = [];
  private currentTokenIndex = 0;

  // Minimum remaining calls before rotating to next token
  private readonly MIN_REMAINING_CALLS = 100;

  // Maximum consecutive errors before marking token as inactive
  private readonly MAX_CONSECUTIVE_ERRORS = 3;

  // Delay between checking if tokens can be reactivated (ms)
  private readonly TOKEN_REACTIVATION_CHECK_INTERVAL = 60 * 1000; // 1 minute

  // Interval ID for the reactivation check
  private reactivationIntervalId: NodeJS.Timeout | null = null;

  // State persistence file path
  private readonly STATE_FILE_PATH = path.join(process.cwd(), 'data', 'github-token-state.json');

  // Flag to track if persistence is enabled
  private persistenceEnabled = false;

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    // Create data directory if it doesn't exist
    const dataDir = path.dirname(this.STATE_FILE_PATH);
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
        this.persistenceEnabled = true;
      } catch (error) {
        logger.warn('Failed to create data directory for token state persistence', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
    } else {
      this.persistenceEnabled = true;
    }

    // First try to load saved state
    const loaded = this.loadTokenState();

    // If no saved state or loading failed, initialize from environment
    if (!loaded) {
      this.initializeTokens();
    }

    // Start the token reactivation check
    this.startTokenReactivationCheck();

    // Register shutdown handler
    this.registerShutdownHandler();
  }

  /**
   * Get the singleton instance
   * @returns The token manager instance
   */
  public static getInstance(): GitHubTokenManager {
    if (!GitHubTokenManager.instance) {
      GitHubTokenManager.instance = new GitHubTokenManager();
    }
    return GitHubTokenManager.instance;
  }

  /**
   * Initialize tokens from environment variables or configuration
   */
  private initializeTokens(): void {
    // Get token string from environment (comma-separated tokens)
    const tokenString = process.env.GITHUB_API_TOKENS || '';

    if (!tokenString) {
      logger.warn('No GitHub API tokens configured. Using unauthenticated API calls with lower rate limits.');
      return;
    }

    // Split and trim tokens
    const tokenValues = tokenString
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    if (tokenValues.length === 0) {
      logger.warn('No valid GitHub API tokens found. Using unauthenticated API calls with lower rate limits.');
      return;
    }

    // Initialize token metrics
    this.tokens = tokenValues.map(token => ({
      token,
      remaining: 5000, // Default GitHub rate limit for authenticated requests
      resetAt: Date.now() + 3600000, // Default reset time (1 hour from now)
      lastUsed: 0,
      consecutiveErrors: 0,
      isActive: true
    }));

    logger.info(`Initialized ${this.tokens.length} GitHub API tokens`);

    // Validate tokens asynchronously
    this.validateTokens();
  }

  /**
   * Load token state from persistence
   * @returns True if state was loaded successfully, false otherwise
   */
  private loadTokenState(): boolean {
    if (!this.persistenceEnabled) return false;

    try {
      if (fs.existsSync(this.STATE_FILE_PATH)) {
        const stateData = fs.readFileSync(this.STATE_FILE_PATH, 'utf8');
        const savedState = JSON.parse(stateData);

        // Validate the state has the expected format
        if (Array.isArray(savedState) && savedState.length > 0) {
          // Filter out any malformed entries
          this.tokens = savedState.filter(token =>
            typeof token.token === 'string' &&
            typeof token.remaining === 'number' &&
            typeof token.resetAt === 'number'
          );

          // Reset tokens that have had their rate limits reset
          const now = Date.now();
          for (const token of this.tokens) {
            if (now >= token.resetAt) {
              token.remaining = 5000;
              token.resetAt = now + 3600000;
            }
          }

          logger.info(`Loaded ${this.tokens.length} GitHub tokens from persistent storage`);
          return this.tokens.length > 0;
        }
      }
    } catch (error) {
      logger.error('Failed to load token state from persistence', {
        error: error instanceof Error ? error.message : String(error)
      });
    }

    return false;
  }

  /**
   * Save current token state to persistence
   */
  private saveTokenState(): void {
    if (!this.persistenceEnabled) return;

    try {
      // Create sanitized state (remove the token string for security)
      const sanitizedState = this.tokens.map(token => ({
        ...token,
        // Hash the token for identification without exposing it
        token: this.hashToken(token.token)
      }));

      // Write to temporary file first to avoid corruption
      const tempPath = `${this.STATE_FILE_PATH}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(sanitizedState, null, 2), 'utf8');

      // Atomically replace the original file
      fs.renameSync(tempPath, this.STATE_FILE_PATH);
    } catch (error) {
      logger.error('Failed to save token state to persistence', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Create a secure hash of a token for identification without exposing it
   * @param token - The token to hash
   * @returns A hash of the token
   */
  private hashToken(token: string): string {
    const hash = require('crypto').createHash('sha256');
    hash.update(token);
    return hash.digest('hex').substring(0, 16); // First 16 chars is enough
  }

  /**
   * Validate all tokens to ensure they are working and update rate limits
   */
  private async validateTokens(): Promise<void> {
    // Use Set to track tokens we've seen to avoid duplicates
    const uniqueTokens = new Set<string>();
    let validTokenCount = 0;

    for (let i = 0; i < this.tokens.length; i++) {
      // Skip duplicate tokens
      if (uniqueTokens.has(this.tokens[i].token)) {
        logger.warn(`Skipping duplicate GitHub token: ${this.maskToken(this.tokens[i].token)}`);
        this.tokens[i].isActive = false;
        continue;
      }

      uniqueTokens.add(this.tokens[i].token);

      try {
        // Check token validity with exponential backoff retry
        const rateLimitInfo = await this.fetchRateLimitInfoWithRetry(this.tokens[i].token);

        // Update token metrics with rate limit information
        this.tokens[i].remaining = rateLimitInfo.remaining;
        this.tokens[i].resetAt = rateLimitInfo.reset * 1000; // Convert to milliseconds
        this.tokens[i].consecutiveErrors = 0;
        this.tokens[i].isActive = true;
        this.tokens[i].errorType = undefined;

        validTokenCount++;

        logger.debug(`Validated GitHub token ${this.maskToken(this.tokens[i].token)}`, {
          remaining: rateLimitInfo.remaining,
          resetAt: new Date(this.tokens[i].resetAt).toISOString()
        });

        // Avoid hitting rate limits during validation
        await setTimeout(100);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorType = this.categorizeError(error);

        logger.error(`Failed to validate GitHub token ${this.maskToken(this.tokens[i].token)}`, {
          error: errorMessage,
          errorType
        });

        this.tokens[i].consecutiveErrors++;
        this.tokens[i].errorType = errorType;

        // If authentication error, immediately invalidate the token
        if (errorType === 'auth') {
          this.tokens[i].isActive = false;
          logger.warn(`Deactivated GitHub token ${this.maskToken(this.tokens[i].token)} due to authentication failure`);
        } else if (this.tokens[i].consecutiveErrors >= this.MAX_CONSECUTIVE_ERRORS) {
          this.tokens[i].isActive = false;
          logger.warn(`Deactivated GitHub token ${this.maskToken(this.tokens[i].token)} due to consecutive errors`);
        }
      }
    }

    // Save token state after validation
    this.saveTokenState();

    // Log overall token status
    const activeTokens = this.tokens.filter(t => t.isActive).length;
    logger.info(`GitHub token validation complete: ${activeTokens}/${this.tokens.length} tokens active`);

    // Check if we have enough valid tokens
    if (validTokenCount === 0 && this.tokens.length > 0) {
      logger.error('All GitHub tokens are invalid! API operations may fail or be severely rate-limited.');
      // Trigger an alert or notification here if you have monitoring systems
    }
  }

  /**
 * Fetch rate limit information from GitHub API
 * @param token - The GitHub token to check
 * @returns Rate limit information
 */
  private async fetchRateLimitInfo(token: string): Promise<IGitHubRateLimit> {
    try {
      const response = await axios.get('https://api.github.com/rate_limit', {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'XcelCrowd-AI-Evaluation'
        },
        timeout: 5000 // 5 second timeout
      });

      // Extract rate limit info from response
      const rateLimitInfo = response.data.resources.core;

      return {
        limit: rateLimitInfo.limit,
        remaining: rateLimitInfo.remaining,
        reset: rateLimitInfo.reset,
        used: rateLimitInfo.used
      };
    } catch (error) {
      logger.error(`Error fetching rate limit info: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Fetch rate limit info with retry for transient errors
   * @param token - The GitHub token
   * @returns Rate limit information
   */
  private async fetchRateLimitInfoWithRetry(token: string): Promise<IGitHubRateLimit> {
    const maxRetries = 3;
    let retryCount = 0;
    let lastError: any;

    while (retryCount < maxRetries) {
      try {
        return await this.fetchRateLimitInfo(token);
      } catch (error) {
        lastError = error;

        // Don't retry auth errors
        if (this.categorizeError(error) === 'auth') {
          throw error;
        }

        // Exponential backoff
        const delayMs = Math.pow(2, retryCount) * 500;
        await setTimeout(delayMs);
        retryCount++;
      }
    }

    // If we reach here, all retries failed
    throw lastError;
  }

  /**
   * Categorize an error for better error handling
   * @param error - The error to categorize
   * @returns The error category
   */
  private categorizeError(error: any): string {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        // Server responded with error status
        if (error.response.status === 401 || error.response.status === 403) {
          return 'auth';
        } else if (error.response.status === 404) {
          return 'not_found';
        } else if (error.response.status >= 500) {
          return 'server';
        }
      } else if (error.request) {
        // Request made but no response received
        return 'network';
      }
    }

    // Generic error type
    return 'unknown';
  }

  /**
   * Start periodic check to reactivate tokens after their rate limits reset
   */
  private startTokenReactivationCheck(): void {
    if (this.reactivationIntervalId) {
      clearInterval(this.reactivationIntervalId);
    }

    this.reactivationIntervalId = setInterval(() => {
      this.checkAndReactivateTokens();

      // Save token state after reactivation check
      this.saveTokenState();
    }, this.TOKEN_REACTIVATION_CHECK_INTERVAL);

    // Ensure the interval doesn't prevent Node from exiting
    this.reactivationIntervalId.unref();
  }

  /**
   * Register handlers for graceful shutdown
   */
  private registerShutdownHandler(): void {
    // Handle normal exit
    process.on('exit', () => {
      this.cleanup();
    });

    // Handle CTRL+C
    process.on('SIGINT', () => {
      this.cleanup();
      process.exit(0);
    });

    // Handle nodemon restart
    process.on('SIGUSR2', () => {
      this.cleanup();
      process.kill(process.pid, 'SIGUSR2');
    });

    // Handle uncaught exceptions - save state before crash
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception in GitHub token manager', { error });
      this.cleanup();
    });
  }

  /**
   * Check and reactivate tokens that have had their rate limits reset
   */
  private checkAndReactivateTokens(): void {
    const now = Date.now();
    let reactivatedCount = 0;
    let refreshedCount = 0;

    for (let i = 0; i < this.tokens.length; i++) {
      // If token is inactive and reset time has passed
      if (!this.tokens[i].isActive && now >= this.tokens[i].resetAt) {
        // Skip tokens with authentication errors - they won't recover automatically
        if (this.tokens[i].errorType === 'auth') {
          continue;
        }

        // Reactivate token
        this.tokens[i].isActive = true;
        this.tokens[i].remaining = 5000; // Reset to default limit
        this.tokens[i].consecutiveErrors = 0;
        reactivatedCount++;

        logger.info(`Reactivated GitHub token ${this.maskToken(this.tokens[i].token)}`);
      }
      // For active tokens, refresh remaining calls if reset time has passed
      else if (this.tokens[i].isActive && now >= this.tokens[i].resetAt) {
        this.tokens[i].remaining = 5000; // Reset to default limit
        this.tokens[i].resetAt = now + 3600000; // 1 hour from now
        refreshedCount++;
      }
    }

    if (reactivatedCount > 0) {
      logger.info(`Reactivated ${reactivatedCount} GitHub tokens`);
    }

    if (refreshedCount > 0) {
      logger.debug(`Refreshed rate limits for ${refreshedCount} GitHub tokens`);
    }

    // If we have no active tokens, try to validate them explicitly
    // This helps recover from temporary network issues
    if (this.tokens.filter(t => t.isActive).length === 0 && this.tokens.length > 0) {
      logger.warn('No active GitHub tokens available. Attempting re-validation...');
      this.validateTokens();
    }
  }

  /**
   * Get the next available token using an improved rotation strategy
   * @returns The next available token or undefined if no tokens are available
   */
  public getNextToken(): string | undefined {
    // If no tokens are configured, return undefined
    if (this.tokens.length === 0) {
      return undefined;
    }

    // Count number of active tokens
    const activeTokens = this.tokens.filter(t => t.isActive);
    if (activeTokens.length === 0) {
      // Try to reactivate tokens that have had their rate limits reset
      this.checkAndReactivateTokens();

      // Check again if we have active tokens
      const activeTokens = this.tokens.filter(t => t.isActive);
      if (activeTokens.length === 0) {
        logger.warn('No active GitHub tokens available. Using unauthenticated API calls.');
        return undefined;
      }
    }

    // Find the next available token using improved rotation strategy
    const now = Date.now();
    const startIndex = this.currentTokenIndex;
    let selectedIndex = -1;

    // First pass: Look for tokens with highest remaining calls
    let maxRemaining = this.MIN_REMAINING_CALLS;
    for (let i = 0; i < this.tokens.length; i++) {
      const index = (startIndex + i) % this.tokens.length;
      const token = this.tokens[index];

      // Skip inactive tokens
      if (!token.isActive) {
        continue;
      }

      // If reset time has passed, assume full rate limit
      if (now >= token.resetAt) {
        token.remaining = 5000;
        token.resetAt = now + 3600000; // 1 hour from now
      }

      // Look for token with highest remaining calls
      if (token.remaining > maxRemaining) {
        maxRemaining = token.remaining;
        selectedIndex = index;
      }
    }

    // Second pass: If no token with sufficient calls, use any active token
    if (selectedIndex === -1) {
      for (let i = 0; i < this.tokens.length; i++) {
        const index = (startIndex + i) % this.tokens.length;
        if (this.tokens[index].isActive) {
          selectedIndex = index;
          break;
        }
      }
    }

    // If still no token found, return undefined (should not happen)
    if (selectedIndex === -1) {
      return undefined;
    }

    // Update token usage metrics
    this.tokens[selectedIndex].lastUsed = now;
    this.tokens[selectedIndex].remaining--; // Decrement remaining calls

    // Update current token index for next time
    this.currentTokenIndex = (selectedIndex + 1) % this.tokens.length;

    // Save token state periodically
    if (Math.random() < 0.01) { // ~1% of calls to reduce disk I/O
      this.saveTokenState();
    }

    return this.tokens[selectedIndex].token;
  }

  /**
   * Update metrics for a token after use
   * @param token - The token that was used
   * @param success - Whether the request was successful
   * @param rateLimitRemaining - The remaining rate limit (if available)
   * @param rateLimitReset - The rate limit reset time (if available)
   */
  public updateTokenMetrics(
    token: string,
    success: boolean,
    rateLimitRemaining?: number,
    rateLimitReset?: number,
    errorType?: string
  ): void {
    const tokenIndex = this.tokens.findIndex(t => t.token === token);
    if (tokenIndex === -1) {
      return;
    }

    if (success) {
      // Reset consecutive errors
      this.tokens[tokenIndex].consecutiveErrors = 0;
      this.tokens[tokenIndex].errorType = undefined;

      // Update rate limit information if provided
      if (rateLimitRemaining !== undefined) {
        this.tokens[tokenIndex].remaining = rateLimitRemaining;
      }

      if (rateLimitReset !== undefined) {
        this.tokens[tokenIndex].resetAt = rateLimitReset * 1000; // Convert to milliseconds
      }
    } else {
      // Increment consecutive errors
      this.tokens[tokenIndex].consecutiveErrors++;

      // Set error type if provided
      if (errorType) {
        this.tokens[tokenIndex].errorType = errorType;
      }

      // If authentication error, immediately deactivate token
      if (errorType === 'auth') {
        this.tokens[tokenIndex].isActive = false;
        logger.warn(`Deactivated GitHub token ${this.maskToken(token)} due to authentication failure`);
      }
      // If too many consecutive errors, mark token as inactive
      else if (this.tokens[tokenIndex].consecutiveErrors >= this.MAX_CONSECUTIVE_ERRORS) {
        this.tokens[tokenIndex].isActive = false;
        logger.warn(`Deactivated GitHub token ${this.maskToken(token)} due to consecutive errors`);
      }
    }

    // Save token state periodically after updates
    if (Math.random() < 0.05) { // ~5% of updates to reduce disk I/O
      this.saveTokenState();
    }
  }

  /**
   * Get token statistics for monitoring
   * @returns Token statistics for monitoring
   */
  public getTokenStats(): {
    totalTokens: number;
    activeTokens: number;
    totalRemaining: number;
    nextResetAt: Date | null;
    healthStatus: 'healthy' | 'degraded' | 'critical';
  } {
    const activeTokens = this.tokens.filter(t => t.isActive);
    const totalRemaining = activeTokens.reduce((sum, token) => sum + token.remaining, 0);

    // Find earliest reset time
    let nextResetAt: number | null = null;
    for (const token of activeTokens) {
      if (nextResetAt === null || token.resetAt < nextResetAt) {
        nextResetAt = token.resetAt;
      }
    }

    // Determine health status
    let healthStatus: 'healthy' | 'degraded' | 'critical';

    if (activeTokens.length === 0) {
      healthStatus = 'critical';
    } else if (activeTokens.length < this.tokens.length * 0.5) {
      healthStatus = 'degraded';
    } else if (totalRemaining < 1000) {
      healthStatus = 'degraded';
    } else {
      healthStatus = 'healthy';
    }

    return {
      totalTokens: this.tokens.length,
      activeTokens: activeTokens.length,
      totalRemaining,
      nextResetAt: nextResetAt !== null ? new Date(nextResetAt) : null,
      healthStatus
    };
  }

  /**
   * Force re-validation of all tokens
   * Useful for health checks or recovery
   */
  public async forceValidateTokens(): Promise<void> {
    logger.info('Forcing validation of all GitHub tokens');
    await this.validateTokens();
  }

  /**
   * Mask a token for secure logging
   * @param token - The token to mask
   * @returns The masked token
   */
  private maskToken(token: string): string {
    if (token.length <= 8) {
      return '***';
    }
    return token.substring(0, 4) + '...' + token.substring(token.length - 4);
  }

  /**
   * Cleanup resources when shutting down
   */
  public cleanup(): void {
    logger.info('Cleaning up GitHub token manager resources');

    if (this.reactivationIntervalId) {
      clearInterval(this.reactivationIntervalId);
      this.reactivationIntervalId = null;
    }

    // Save final token state
    this.saveTokenState();
  }
}

// Export singleton instance
export const githubTokenManager = GitHubTokenManager.getInstance();