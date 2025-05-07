import { logger } from '../utils/logger';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from './config.env.validation';

/**
 * Supported LLM providers
 */
export enum LLMProvider {
  OPENAI = 'openai',
  ANTHROPIC = 'anthropic',
  AZURE_OPENAI = 'azureOpenai'
}

/**
 * Interface for API key metrics and usage tracking
 */
interface IAPIKeyMetrics {
  // Masked version for logs (for security)
  keyId: string;
  // Encrypted version of the full key
  encryptedKey: string;
  // Provider this key belongs to
  provider: LLMProvider;
  // Number of requests remaining before rate limit
  remainingRequests: number;
  // Time when rate limits reset (unix timestamp)
  resetAt: number;
  // Last time this key was used
  lastUsed: number;
  // Track consecutive errors for circuit breaking
  consecutiveErrors: number;
  // Whether this key is currently active
  isActive: boolean;
  // Reason for deactivation if not active
  deactivationReason?: string;
  // Tracks the last error encountered
  lastErrorType?: string;
  // Tracks token usage for cost analysis
  tokenUsage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    estimatedCost: number;
  };
  // Tracks request success/failure rates
  requestStats: {
    success: number;
    failed: number;
    totalRequests: number;
  };
}

/**
 * Rate limit information returned by providers
 */
interface IRateLimit {
  limit: number;
  remaining: number;
  reset: number;
}

/**
 * Enterprise-grade LLM token manager with token rotation, encryption, and cost tracking
 * Implements circuit breaking patterns and advanced monitoring
 */
export class LLMTokenManager {
  private static instance: LLMTokenManager;
  private apiKeys: Map<LLMProvider, IAPIKeyMetrics[]> = new Map();
  private currentKeyIndices: Map<LLMProvider, number> = new Map();

  // Encryption key for storing API keys (derived from app secret)
  private encryptionKey!: Buffer;
  private encryptionIV!: Buffer;

  // Minimum remaining calls before rotating to next key
  private readonly MIN_REMAINING_CALLS = 10;

  // Maximum consecutive errors before marking token as inactive
  private readonly MAX_CONSECUTIVE_ERRORS = 3;

  // Delay between checking if keys can be reactivated (ms)
  private readonly KEY_REACTIVATION_CHECK_INTERVAL = 60 * 1000; // 1 minute

  // Interval ID for the reactivation check
  private reactivationIntervalId: NodeJS.Timeout | null = null;

  // State persistence file path
  private readonly STATE_FILE_PATH = path.join(process.cwd(), 'data', 'llm-token-state.enc');

  // Flag to track if persistence is enabled
  private persistenceEnabled = false;

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    // Initialize encryption
    this.initializeEncryption();

    // Create data directory if it doesn't exist
    const dataDir = path.dirname(this.STATE_FILE_PATH);
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
        this.persistenceEnabled = true;
      } catch (error) {
        logger.warn('Failed to create data directory for LLM API key state persistence', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
    } else {
      this.persistenceEnabled = true;
    }

    // Initialize providers map
    Object.values(LLMProvider).forEach(provider => {
      this.apiKeys.set(provider, []);
      this.currentKeyIndices.set(provider, 0);
    });

    // First try to load saved state
    const loaded = this.loadKeyState();

    // If no saved state or loading failed, initialize from environment
    if (!loaded) {
      this.initializeAPIKeys();
    }

    // Start the key reactivation check
    this.startKeyReactivationCheck();

    // Register shutdown handler
    this.registerShutdownHandler();
  }

  /**
   * Initialize encryption using app secret
   */
  private initializeEncryption(): void {
    try {
      // Generate a stable key from the JWT secret
      const hash = crypto.createHash('sha256');
      hash.update(config.jwtSecret);
      this.encryptionKey = hash.digest().subarray(0, 32); // 256 bits (32 bytes)
      
      // Generate a stable IV (not secure for true encryption, but sufficient for obfuscation)
      const ivHash = crypto.createHash('md5');
      ivHash.update(config.jwtSecret);
      this.encryptionIV = ivHash.digest(); // 128 bits (16 bytes)
    } catch (error) {
      logger.error('Failed to initialize encryption', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new Error('Failed to initialize API key encryption');
    }
  }

  /**
   * Encrypt an API key
   * @param apiKey - The API key to encrypt
   * @returns The encrypted key
   */
  private encryptKey(apiKey: string): string {
    try {
      const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, this.encryptionIV);
      let encrypted = cipher.update(apiKey, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return encrypted;
    } catch (error) {
      logger.error('Failed to encrypt API key', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new Error('Failed to encrypt API key');
    }
  }

  /**
   * Decrypt an API key
   * @param encryptedKey - The encrypted API key
   * @returns The decrypted key
   */
  private decryptKey(encryptedKey: string): string {
    try {
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, this.encryptionIV);
      let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      logger.error('Failed to decrypt API key', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new Error('Failed to decrypt API key');
    }
  }

  /**
   * Get the singleton instance
   * @returns The token manager instance
   */
  public static getInstance(): LLMTokenManager {
    if (!LLMTokenManager.instance) {
      LLMTokenManager.instance = new LLMTokenManager();
    }
    return LLMTokenManager.instance;
  }

  /**
   * Initialize API keys from configuration
   */
  private initializeAPIKeys(): void {
    try {
      // Initialize OpenAI keys
      this.initializeProviderKeys(
        LLMProvider.OPENAI, 
        config.ai.openai.apiKeys, 
        5000, // Default OpenAI rate limit (may vary)
        3600000 // 1 hour reset time
      );

      // Initialize Anthropic keys
      this.initializeProviderKeys(
        LLMProvider.ANTHROPIC, 
        config.ai.anthropic.apiKeys, 
        1000, // Default Anthropic rate limit (may vary)
        3600000 // 1 hour reset time
      );

      // Initialize Azure OpenAI keys
      this.initializeProviderKeys(
        LLMProvider.AZURE_OPENAI, 
        config.ai.azureOpenai.apiKeys, 
        5000, // Default Azure OpenAI rate limit (may vary)
        3600000 // 1 hour reset time
      );

      // Validate keys asynchronously
      this.validateAllAPIKeys();
    } catch (error) {
      logger.error('Failed to initialize LLM API keys', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Initialize keys for a specific provider
   * @param provider - The LLM provider
   * @param keys - Array of API keys
   * @param defaultLimit - Default rate limit
   * @param defaultResetTime - Default reset time in ms
   */
  private initializeProviderKeys(
    provider: LLMProvider, 
    keys: string[], 
    defaultLimit: number, 
    defaultResetTime: number
  ): void {
    if (!keys || keys.length === 0) {
      logger.warn(`No API keys configured for ${provider}`);
      return;
    }

    const providerKeys: IAPIKeyMetrics[] = [];

    // Initialize key metrics for each key
    for (const key of keys) {
      if (!key || key.length === 0) continue;

      providerKeys.push({
        keyId: this.generateKeyId(key),
        encryptedKey: this.encryptKey(key),
        provider,
        remainingRequests: defaultLimit,
        resetAt: Date.now() + defaultResetTime,
        lastUsed: 0,
        consecutiveErrors: 0,
        isActive: true,
        tokenUsage: {
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
          estimatedCost: 0
        },
        requestStats: {
          success: 0,
          failed: 0,
          totalRequests: 0
        }
      });
    }

    this.apiKeys.set(provider, providerKeys);
    logger.info(`Initialized ${providerKeys.length} API keys for ${provider}`);
  }

  /**
   * Generate a secure key ID for logging (masks the actual key)
   * @param key - The API key
   * @returns A secure key ID
   */
  private generateKeyId(key: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(key);
    const hashDigest = hash.digest('hex').substring(0, 8);
    
    // Include masked portion of the key (first 2 and last 2 chars)
    if (key.length >= 10) {
      return `${key.substring(0, 2)}...${key.substring(key.length - 2)}[${hashDigest}]`;
    }
    
    return `key[${hashDigest}]`;
  }

  /**
   * Load key state from persistence
   * @returns True if state was loaded successfully, false otherwise
   */
  private loadKeyState(): boolean {
    if (!this.persistenceEnabled) return false;

    try {
      if (fs.existsSync(this.STATE_FILE_PATH)) {
        // Read encrypted data
        const encryptedData = fs.readFileSync(this.STATE_FILE_PATH, 'utf8');
        
        // Decrypt the data
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, this.encryptionIV);
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        const savedState = JSON.parse(decrypted);

        // Validate the state has the expected format
        if (typeof savedState === 'object' && savedState !== null) {
          let totalKeys = 0;
          
          // Initialize the providers map
          Object.values(LLMProvider).forEach(provider => {
            if (Array.isArray(savedState[provider])) {
              // Filter out any malformed entries
              const providerKeys = savedState[provider].filter((key: any) =>
                typeof key.keyId === 'string' &&
                typeof key.encryptedKey === 'string' &&
                typeof key.remainingRequests === 'number' &&
                typeof key.resetAt === 'number'
              );
              
              this.apiKeys.set(provider, providerKeys);
              totalKeys += providerKeys.length;
              
              // Reset keys that have had their rate limits reset
              const now = Date.now();
              for (const key of providerKeys) {
                if (now >= key.resetAt) {
                  key.remainingRequests = provider === LLMProvider.OPENAI ? 5000 : 
                    (provider === LLMProvider.ANTHROPIC ? 1000 : 5000);
                  key.resetAt = now + 3600000;
                }
              }
            }
          });
          
          logger.info(`Loaded ${totalKeys} LLM API keys from persistent storage`);
          return totalKeys > 0;
        }
      }
    } catch (error) {
      logger.error('Failed to load LLM API key state from persistence', {
        error: error instanceof Error ? error.message : String(error)
      });
    }

    return false;
  }

  /**
   * Save current key state to persistence
   */
  private saveKeyState(): void {
    if (!this.persistenceEnabled) return;

    try {
      // Create state object
      const state: Record<string, any> = {};
      
      // Add all provider keys to state
      for (const [provider, keys] of this.apiKeys.entries()) {
        state[provider] = keys;
      }
      
      // Convert to JSON string
      const stateJson = JSON.stringify(state);
      
      // Encrypt the data
      const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, this.encryptionIV);
      let encrypted = cipher.update(stateJson, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Write to temporary file first to avoid corruption
      const tempPath = `${this.STATE_FILE_PATH}.tmp`;
      fs.writeFileSync(tempPath, encrypted, 'utf8');
      
      // Rename to actual file (atomic operation)
      fs.renameSync(tempPath, this.STATE_FILE_PATH);
      
      logger.debug('Saved LLM API key state to persistent storage');
    } catch (error) {
      logger.error('Failed to save LLM API key state', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Validate all API keys
   */
  private async validateAllAPIKeys(): Promise<void> {
    logger.info('Validating all LLM API keys');
    
    for (const provider of Object.values(LLMProvider)) {
      const keys = this.apiKeys.get(provider) || [];
      
      for (const keyMetrics of keys) {
        await this.validateAPIKey(provider, this.decryptKey(keyMetrics.encryptedKey));
      }
    }
  }

  /**
   * Validate a single API key
   * @param provider - The LLM provider
   * @param apiKey - The API key to validate
   */
  private async validateAPIKey(provider: LLMProvider, apiKey: string): Promise<void> {
    try {
      const rateLimit = await this.fetchRateLimitInfo(provider, apiKey);
      
      // Update key metrics
      this.updateKeyMetrics(
        provider,
        apiKey,
        true, // success
        rateLimit.remaining,
        rateLimit.reset * 1000 // convert to ms
      );
      
      logger.debug(`Validated API key for ${provider}`, {
        provider,
        keyId: this.generateKeyId(apiKey),
        remaining: rateLimit.remaining,
        resetAt: new Date(rateLimit.reset * 1000).toISOString()
      });
    } catch (error) {
      // Get error type
      const errorType = this.categorizeError(error);
      
      // Update key metrics with error
      this.updateKeyMetrics(
        provider,
        apiKey,
        false, // failure
        undefined,
        undefined,
        errorType
      );
      
      logger.error(`Failed to validate API key for ${provider}`, {
        provider,
        keyId: this.generateKeyId(apiKey),
        errorType,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Fetch rate limit information from the provider
   * @param provider - The LLM provider
   * @param apiKey - The API key
   * @returns Rate limit information
   */
  private async fetchRateLimitInfo(provider: LLMProvider, apiKey: string): Promise<IRateLimit> {
    switch (provider) {
      case LLMProvider.OPENAI:
        return this.fetchOpenAIRateLimit(apiKey);
      case LLMProvider.ANTHROPIC:
        return this.fetchAnthropicRateLimit(apiKey);
      case LLMProvider.AZURE_OPENAI:
        return this.fetchAzureOpenAIRateLimit(apiKey);
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  }

  /**
   * Fetch rate limit info from OpenAI
   * @param apiKey - The OpenAI API key
   * @returns Rate limit information
   */
  private async fetchOpenAIRateLimit(apiKey: string): Promise<IRateLimit> {
    try {
      const response = await axios({
        method: 'get',
        url: 'https://api.openai.com/v1/models',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000 // 10 second timeout
      });

      // Extract rate limit headers
      const rateLimit = parseInt(response.headers['x-ratelimit-limit'] || '5000', 10);
      const rateRemaining = parseInt(response.headers['x-ratelimit-remaining'] || '5000', 10);
      const rateReset = parseInt(response.headers['x-ratelimit-reset'] || 
                                ((Date.now() / 1000) + 3600).toString(), 10);

      return {
        limit: rateLimit,
        remaining: rateRemaining,
        reset: rateReset
      };
    } catch (error) {
      logger.error('Failed to fetch OpenAI rate limit', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Fetch rate limit info from Anthropic
   * @param apiKey - The Anthropic API key
   * @returns Rate limit information
   */
  private async fetchAnthropicRateLimit(apiKey: string): Promise<IRateLimit> {
    try {
      const response = await axios({
        method: 'get',
        url: 'https://api.anthropic.com/v1/models',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json'
        },
        timeout: 10000 // 10 second timeout
      });

      // Anthropic doesn't expose rate limits in headers, use defaults
      return {
        limit: 1000, // Default value
        remaining: 1000, // Assume maximum
        reset: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      };
    } catch (error) {
      logger.error('Failed to fetch Anthropic rate limit', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Fetch rate limit info from Azure OpenAI
   * @param apiKey - The Azure OpenAI API key
   * @returns Rate limit information
   */
  private async fetchAzureOpenAIRateLimit(apiKey: string): Promise<IRateLimit> {
    if (!config.ai.azureOpenai.endpoint) {
      throw new Error('Azure OpenAI endpoint not configured');
    }

    try {
      const response = await axios({
        method: 'get',
        url: `${config.ai.azureOpenai.endpoint}/openai/models?api-version=2023-12-01-preview`,
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/json'
        },
        timeout: 10000 // 10 second timeout
      });

      // Azure doesn't expose rate limits in headers, use defaults
      return {
        limit: 5000, // Default value
        remaining: 5000, // Assume maximum
        reset: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      };
    } catch (error) {
      logger.error('Failed to fetch Azure OpenAI rate limit', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Categorize an error for better tracking and handling
   * @param error - The error object
   * @returns Error type string
   */
  private categorizeError(error: any): string {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      
      if (status === 401 || status === 403) return 'AUTH_ERROR';
      if (status === 429) return 'RATE_LIMIT';
      if (typeof status === 'number' && status >= 500) return 'SERVER_ERROR';
      if (typeof status === 'number' && status >= 400) return 'CLIENT_ERROR';
      
      return 'NETWORK_ERROR';
    }
    
    if (error instanceof Error) {
      if (error.message.includes('timeout')) return 'TIMEOUT';
      if (error.message.includes('network')) return 'NETWORK_ERROR';
    }
    
    return 'UNKNOWN_ERROR';
  }

  /**
   * Start periodic check to reactivate keys that were temporarily deactivated
   */
  private startKeyReactivationCheck(): void {
    if (this.reactivationIntervalId) {
      clearInterval(this.reactivationIntervalId);
    }
    
    this.reactivationIntervalId = setInterval(() => {
      this.checkAndReactivateKeys();
    }, this.KEY_REACTIVATION_CHECK_INTERVAL);
    
    logger.debug('Started LLM API key reactivation check interval');
  }

  /**
   * Register shutdown handler to save state on process exit
   */
  private registerShutdownHandler(): void {
    process.on('SIGTERM', () => this.cleanup());
    process.on('SIGINT', () => this.cleanup());
    process.on('exit', () => this.cleanup());
    
    logger.debug('Registered LLM token manager shutdown handlers');
  }

  /**
   * Check and reactivate keys that can be reactivated
   */
  private checkAndReactivateKeys(): void {
    const now = Date.now();
    let reactivatedCount = 0;
    
    // Check each provider
    for (const [provider, keys] of this.apiKeys.entries()) {
      for (const key of keys) {
        // Skip active keys
        if (key.isActive) continue;
        
        // If reset time has passed, reactivate the key
        if (now >= key.resetAt) {
          key.isActive = true;
          key.consecutiveErrors = 0;
          key.deactivationReason = undefined;
          key.remainingRequests = provider === LLMProvider.OPENAI ? 5000 : 
            (provider === LLMProvider.ANTHROPIC ? 1000 : 5000);
          key.resetAt = now + 3600000; // 1 hour
          
          reactivatedCount++;
          
          logger.info(`Reactivated LLM API key for ${provider}`, {
            provider,
            keyId: key.keyId
          });
        }
      }
    }
    
    if (reactivatedCount > 0) {
      logger.info(`Reactivated ${reactivatedCount} LLM API keys`);
      this.saveKeyState();
    }
  }

  /**
   * Get the next available API key for a provider
   * @param provider - The LLM provider
   * @returns The API key or undefined if none available
   */
  public getNextAPIKey(provider: LLMProvider): string | undefined {
    const keys = this.apiKeys.get(provider);
    
    if (!keys || keys.length === 0) {
      logger.warn(`No API keys available for ${provider}`);
      return undefined;
    }
    
    // Get current index
    let currentIndex = this.currentKeyIndices.get(provider) || 0;
    const startIndex = currentIndex;
    let key: IAPIKeyMetrics | undefined;
    
    // Find an active key with remaining quota
    do {
      key = keys[currentIndex];
      
      // Check if key is active and has quota
      if (key.isActive && key.remainingRequests > this.MIN_REMAINING_CALLS) {
        this.currentKeyIndices.set(provider, currentIndex);
        key.lastUsed = Date.now();
        
        // Return the decrypted key
        return this.decryptKey(key.encryptedKey);
      }
      
      // Move to next key
      currentIndex = (currentIndex + 1) % keys.length;
    } while (currentIndex !== startIndex);
    
    // If no key found with enough quota, use the one with most remaining
    let maxRemainingKey: IAPIKeyMetrics | undefined;
    let maxRemaining = 0;
    
    for (const k of keys) {
      if (k.isActive && k.remainingRequests > maxRemaining) {
        maxRemaining = k.remainingRequests;
        maxRemainingKey = k;
      }
    }
    
    if (maxRemainingKey) {
      logger.warn(`Using ${provider} API key with limited remaining quota (${maxRemaining})`);
      maxRemainingKey.lastUsed = Date.now();
      return this.decryptKey(maxRemainingKey.encryptedKey);
    }
    
    // No active keys with remaining quota
    logger.error(`No active ${provider} API keys with remaining quota available`);
    return undefined;
  }

  /**
   * Get the default API key for a provider
   * Same as getNextAPIKey but for convenience
   * @param provider - The LLM provider
   * @returns The API key or undefined if none available
   */
  public getAPIKey(provider: LLMProvider): string | undefined {
    return this.getNextAPIKey(provider);
  }

  /**
   * Update metrics for an API key
   * @param provider - The LLM provider
   * @param apiKey - The API key
   * @param success - Whether the request was successful
   * @param remaining - Remaining requests (optional)
   * @param resetAt - Reset time (optional)
   * @param errorType - Error type if failed (optional)
   */
  public updateKeyMetrics(
    provider: LLMProvider,
    apiKey: string,
    success: boolean,
    remaining?: number,
    resetAt?: number,
    errorType?: string
  ): void {
    const keys = this.apiKeys.get(provider);
    if (!keys) return;
    
    // Generate key ID for lookup
    const keyId = this.generateKeyId(apiKey);
    
    // Find the key in the list
    const keyMetrics = keys.find(k => 
      k.keyId === keyId || this.decryptKey(k.encryptedKey) === apiKey
    );
    
    if (!keyMetrics) {
      logger.warn(`Key metrics not found for ${provider} API key ${keyId}`);
      return;
    }
    
    // Update request stats
    keyMetrics.requestStats.totalRequests++;
    if (success) {
      keyMetrics.requestStats.success++;
      keyMetrics.consecutiveErrors = 0;
    } else {
      keyMetrics.requestStats.failed++;
      keyMetrics.consecutiveErrors++;
      keyMetrics.lastErrorType = errorType;
      
      // Deactivate key if too many consecutive errors
      if (keyMetrics.consecutiveErrors >= this.MAX_CONSECUTIVE_ERRORS) {
        keyMetrics.isActive = false;
        keyMetrics.deactivationReason = `${keyMetrics.consecutiveErrors} consecutive ${errorType} errors`;
        
        logger.warn(`Deactivated ${provider} API key due to consecutive errors`, {
          provider,
          keyId: keyMetrics.keyId,
          consecutiveErrors: keyMetrics.consecutiveErrors,
          errorType
        });
      }
    }
    
    // Update remaining requests if provided
    if (remaining !== undefined) {
      keyMetrics.remainingRequests = remaining;
    } else if (success) {
      // Decrement remaining as a conservative estimate if not provided
      keyMetrics.remainingRequests = Math.max(0, keyMetrics.remainingRequests - 1);
    }
    
    // Update reset time if provided
    if (resetAt !== undefined) {
      keyMetrics.resetAt = resetAt;
    }
    
    // Deactivate if no requests remaining
    if (keyMetrics.remainingRequests <= 0) {
      keyMetrics.isActive = false;
      keyMetrics.deactivationReason = 'Rate limit reached';
      
      logger.warn(`Deactivated ${provider} API key due to rate limit`, {
        provider,
        keyId: keyMetrics.keyId,
        resetAt: new Date(keyMetrics.resetAt).toISOString()
      });
    }
    
    // Save state periodically (every 10 requests)
    if (keyMetrics.requestStats.totalRequests % 10 === 0) {
      this.saveKeyState();
    }
  }

  /**
   * Update token usage metrics for cost tracking
   * @param provider - The LLM provider 
   * @param apiKey - The API key
   * @param promptTokens - Number of prompt tokens
   * @param completionTokens - Number of completion tokens
   */
  public updateTokenUsage(
    provider: LLMProvider,
    apiKey: string,
    promptTokens: number,
    completionTokens: number
  ): void {
    const keys = this.apiKeys.get(provider);
    if (!keys) return;
    
    // Generate key ID for lookup
    const keyId = this.generateKeyId(apiKey);
    
    // Find the key in the list
    const keyMetrics = keys.find(k => 
      k.keyId === keyId || this.decryptKey(k.encryptedKey) === apiKey
    );
    
    if (!keyMetrics) {
      logger.warn(`Key metrics not found for ${provider} API key ${keyId}`);
      return;
    }
    
    // Update token usage
    keyMetrics.tokenUsage.promptTokens += promptTokens;
    keyMetrics.tokenUsage.completionTokens += completionTokens;
    keyMetrics.tokenUsage.totalTokens += (promptTokens + completionTokens);
    
    // Calculate estimated cost
    keyMetrics.tokenUsage.estimatedCost += this.calculateCost(
      provider, 
      promptTokens, 
      completionTokens
    );
  }

  /**
   * Calculate estimated cost of token usage
   * @param provider - The LLM provider
   * @param promptTokens - Number of prompt tokens
   * @param completionTokens - Number of completion tokens
   * @returns Estimated cost in USD
   */
  private calculateCost(
    provider: LLMProvider, 
    promptTokens: number, 
    completionTokens: number
  ): number {
    // These are simplified estimates - actual costs would depend on specific model
    switch (provider) {
      case LLMProvider.OPENAI:
        // Approximated for GPT-4
        return (promptTokens * 0.00003) + (completionTokens * 0.00006);
      case LLMProvider.ANTHROPIC:
        // Approximated for Claude
        return (promptTokens * 0.00008) + (completionTokens * 0.00024);
      case LLMProvider.AZURE_OPENAI:
        // Approximated for Azure OpenAI
        return (promptTokens * 0.00003) + (completionTokens * 0.00006);
      default:
        return 0;
    }
  }

  /**
   * Get statistics about API keys
   * @returns Statistics about API keys
   */
  public getAPIKeyStats(): {
    [provider: string]: {
      totalKeys: number;
      activeKeys: number;
      totalRemaining: number;
      nextResetAt: Date | null;
      healthStatus: 'healthy' | 'degraded' | 'critical';
      estimatedCost: number;
      successRate: number;
    }
  } {
    const stats: any = {};
    
    for (const [provider, keys] of this.apiKeys.entries()) {
      const totalKeys = keys.length;
      const activeKeys = keys.filter(k => k.isActive).length;
      const totalRemaining = keys.reduce((sum, k) => sum + (k.isActive ? k.remainingRequests : 0), 0);
      
      // Find next reset time
      let nextReset: number | null = null;
      for (const k of keys) {
        if (k.isActive && (!nextReset || k.resetAt < nextReset)) {
          nextReset = k.resetAt;
        }
      }
      
      // Calculate total estimated cost
      const estimatedCost = keys.reduce((sum, k) => sum + k.tokenUsage.estimatedCost, 0);
      
      // Calculate success rate
      const totalRequests = keys.reduce((sum, k) => sum + k.requestStats.totalRequests, 0);
      const successRate = totalRequests > 0 
        ? (keys.reduce((sum, k) => sum + k.requestStats.success, 0) / totalRequests) * 100
        : 100;
      
      // Determine health status
      let healthStatus: 'healthy' | 'degraded' | 'critical';
      if (activeKeys === 0) {
        healthStatus = 'critical';
      } else if (activeKeys < totalKeys * 0.5 || successRate < 80) {
        healthStatus = 'degraded';
      } else {
        healthStatus = 'healthy';
      }
      
      stats[provider] = {
        totalKeys,
        activeKeys,
        totalRemaining,
        nextResetAt: nextReset ? new Date(nextReset) : null,
        healthStatus,
        estimatedCost,
        successRate
      };
    }
    
    return stats;
  }

  /**
   * Force validation of all API keys
   */
  public async forceValidateAPIKeys(): Promise<void> {
    await this.validateAllAPIKeys();
  }

  /**
   * Cleanup resources
   */
  public cleanup(): void {
    // Stop reactivation check interval
    if (this.reactivationIntervalId) {
      clearInterval(this.reactivationIntervalId);
      this.reactivationIntervalId = null;
    }
    
    // Save state
    this.saveKeyState();
    
    logger.info('LLM token manager cleaned up');
  }
} 