import { MongoSanitizer } from '../utils/mongo.sanitize';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../models/interfaces';
import { logger } from '../utils/logger';

/**
 * Enterprise-grade GitHub service with robust security validation
 * Provides utilities for GitHub repository operations
 */
export class GitHubService {
  // Allowed GitHub domains whitelist
  private static readonly ALLOWED_GITHUB_DOMAINS = ['github.com', 'www.github.com'];

  /**
   * Extract and validate GitHub repository information from URL
   * @param submissionUrl - The URL submitted by the user
   * @returns Object containing repository information
   * @throws ApiError with appropriate status if validation fails
   */
  public static async extractGitHubRepoInfo(submissionUrl: string): Promise<{
    owner: string;
    repo: string;
    url: string
  }> {
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

  // Additional GitHub utility methods can be added here
}

// Create singleton instance
export const githubService = new GitHubService();