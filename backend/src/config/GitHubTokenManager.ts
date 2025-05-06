import { logger } from '../utils/logger';
import axios from 'axios';
import { setTimeout } from 'timers/promises';

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
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    // Initialize from environment variables or configuration
    this.initializeTokens();
    
    // Start the token reactivation check
    this.startTokenReactivationCheck();
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
   * Validate all tokens to ensure they are working and update rate limits
   */
  private async validateTokens(): Promise<void> {
    for (let i = 0; i < this.tokens.length; i++) {
      try {
        // Check token validity by making a rate limit request
        const rateLimitInfo = await this.fetchRateLimitInfo(this.tokens[i].token);
        
        // Update token metrics with rate limit information
        this.tokens[i].remaining = rateLimitInfo.remaining;
        this.tokens[i].resetAt = rateLimitInfo.reset * 1000; // Convert to milliseconds
        this.tokens[i].consecutiveErrors = 0;
        this.tokens[i].isActive = true;
        
        logger.debug(`Validated GitHub token ${this.maskToken(this.tokens[i].token)}`, {
          remaining: rateLimitInfo.remaining,
          resetAt: new Date(this.tokens[i].resetAt).toISOString()
        });
        
        // Avoid hitting rate limits during validation
        await setTimeout(100);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`Failed to validate GitHub token ${this.maskToken(this.tokens[i].token)}`, {
          error: errorMessage
        });
        
        this.tokens[i].consecutiveErrors++;
        if (this.tokens[i].consecutiveErrors >= this.MAX_CONSECUTIVE_ERRORS) {
          this.tokens[i].isActive = false;
        }
      }
    }
    
    // Log overall token status
    const activeTokens = this.tokens.filter(t => t.isActive).length;
    logger.info(`GitHub token validation complete: ${activeTokens}/${this.tokens.length} tokens active`);
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
    }, this.TOKEN_REACTIVATION_CHECK_INTERVAL);
  }
  
  /**
   * Check and reactivate tokens that have had their rate limits reset
   */
  private checkAndReactivateTokens(): void {
    const now = Date.now();
    let reactivatedCount = 0;
    
    for (let i = 0; i < this.tokens.length; i++) {
      // If token is inactive and reset time has passed
      if (!this.tokens[i].isActive && now >= this.tokens[i].resetAt) {
        // Reactivate token
        this.tokens[i].isActive = true;
        this.tokens[i].remaining = 5000; // Reset to default limit
        this.tokens[i].consecutiveErrors = 0;
        reactivatedCount++;
        
        logger.info(`Reactivated GitHub token ${this.maskToken(this.tokens[i].token)}`);
      }
    }
    
    if (reactivatedCount > 0) {
      logger.info(`Reactivated ${reactivatedCount} GitHub tokens`);
    }
  }
  
  /**
   * Fetch rate limit information from GitHub API
   * @param token - The GitHub API token
   * @returns Rate limit information
   */
  private async fetchRateLimitInfo(token: string): Promise<IGitHubRateLimit> {
    try {
      const response = await axios.get('https://api.github.com/rate_limit', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'XcelCrowd-AI-Evaluation'
        },
        timeout: 5000
      });
      
      return response.data.resources.core as IGitHubRateLimit;
    } catch (error) {
      logger.error(`Error fetching rate limit info for token ${this.maskToken(token)}`, {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }
  
  /**
   * Get the next available token using rotation strategy
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
      logger.warn('No active GitHub tokens available. Using unauthenticated API calls.');
      return undefined;
    }
    
    // Find the next available token using rotation strategy
    const now = Date.now();
    const startIndex = this.currentTokenIndex;
    let selectedIndex = -1;
    
    // First pass: Look for tokens with sufficient remaining calls
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
      
      // If token has sufficient remaining calls, use it
      if (token.remaining > this.MIN_REMAINING_CALLS) {
        selectedIndex = index;
        break;
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
    rateLimitReset?: number
  ): void {
    const tokenIndex = this.tokens.findIndex(t => t.token === token);
    if (tokenIndex === -1) {
      return;
    }
    
    if (success) {
      // Reset consecutive errors
      this.tokens[tokenIndex].consecutiveErrors = 0;
      
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
      
      // If too many consecutive errors, mark token as inactive
      if (this.tokens[tokenIndex].consecutiveErrors >= this.MAX_CONSECUTIVE_ERRORS) {
        this.tokens[tokenIndex].isActive = false;
        logger.warn(`Deactivated GitHub token ${this.maskToken(token)} due to consecutive errors`);
      }
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
    
    return {
      totalTokens: this.tokens.length,
      activeTokens: activeTokens.length,
      totalRemaining,
      nextResetAt: nextResetAt !== null ? new Date(nextResetAt) : null
    };
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
    if (this.reactivationIntervalId) {
      clearInterval(this.reactivationIntervalId);
      this.reactivationIntervalId = null;
    }
  }
}

// Export singleton instance
export const githubTokenManager = GitHubTokenManager.getInstance(); 