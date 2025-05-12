import { singleton } from 'tsyringe';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../utils/logger';
import { config } from '../../config/config.env.validation';
import { LLMProvider, LLMTokenManager } from '../../config/llm.token.manager';
import { ILLMService } from './interfaces/ILLMService';
import { 
  ILLMTextRequest, 
  ILLMTextResponse, 
  ILLMEmbeddingRequest, 
  ILLMEmbeddingResponse,
  ILLMStreamChunk
} from './interfaces/ILLMRequest';
import { ILLMProvider, IModelCapabilities, IModelContextWindow } from './interfaces/ILLMProvider';
import { LLMProviderFactory } from './providers/LLMProviderFactory';
import { LLMCache } from './LLMCache';
import { LLMMetricsCollector } from './monitoring/LLMMetricsCollector';
import { ApiError } from '../../utils/api.error';
import { HTTP_STATUS } from '../../constants';
import { setTimeout } from 'timers/promises';

/**
 * Rate limiter for LLM API calls
 */
class RateLimiter {
  private timestamps: number[] = [];
  private readonly windowMs: number;
  private readonly maxRequests: number;

  constructor(windowMs: number, maxRequests: number) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  /**
   * Check if a request can be made under the rate limit
   * @returns Boolean indicating if request is allowed
   */
  public canMakeRequest(): boolean {
    const now = Date.now();
    // Remove timestamps outside the window
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
    // Check if we're under the limit
    return this.timestamps.length < this.maxRequests;
  }

  /**
   * Record a request
   */
  public recordRequest(): void {
    this.timestamps.push(Date.now());
  }

  /**
   * Get time until next available request slot
   * @returns Time in ms until a slot is available
   */
  public getTimeUntilAvailable(): number {
    if (this.canMakeRequest()) return 0;
    const now = Date.now();
    const oldestTimestamp = this.timestamps[0];
    return this.windowMs - (now - oldestTimestamp);
  }
}

/**
 * Main LLM service implementation
 * Provides a unified interface for working with multiple LLM providers
 */
@singleton()
export class LLMService implements ILLMService {
  private static instance: LLMService;
  private readonly tokenManager: LLMTokenManager;
  private readonly providerFactory: LLMProviderFactory;
  private readonly cache: LLMCache;
  private readonly metrics: LLMMetricsCollector;
  private readonly rateLimiter: RateLimiter;

  /**
   * Constructor
   */
  constructor() {
    this.tokenManager = LLMTokenManager.getInstance();
    this.providerFactory = LLMProviderFactory.getInstance();
    this.cache = LLMCache.getInstance();
    this.metrics = LLMMetricsCollector.getInstance();
    
    // Initialize rate limiter (default: 60 requests per minute)
    const rateLimit = config.ai.global.rateLimitPerMinute;
    this.rateLimiter = new RateLimiter(60 * 1000, rateLimit);
    
    logger.info('LLM service initialized', {
      defaultProvider: config.ai.global.provider,
      cacheEnabled: config.ai.global.cacheEnabled,
      rateLimit
    });
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): LLMService {
    if (!LLMService.instance) {
      LLMService.instance = new LLMService();
    }
    return LLMService.instance;
  }

  /**
   * Generate text using the LLM
   * @param request - Text generation request
   * @returns Text response
   */
  public async generateText(request: ILLMTextRequest): Promise<ILLMTextResponse> {
    // Don't allow streaming with this method
    if (request.stream) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Streaming requests should use generateTextStream method',
        true,
        'INVALID_REQUEST'
      );
    }
    
    // Assign request ID if not provided
    if (!request.requestId) {
      request.requestId = uuidv4();
    }
    
    // Set default values if not provided
    const normalizedRequest = this.normalizeTextRequest(request);
    
    // Try to get from cache first
    try {
      const cachedResponse = await this.cache.getCachedTextResponse(normalizedRequest);
      if (cachedResponse) {
        // Record cache hit in metrics
        this.metrics.recordCacheHit(
          this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
          normalizedRequest.model,
          cachedResponse.usage?.totalTokens || 0,
          normalizedRequest.requestId,
          normalizedRequest.userId
        );
        
        logger.debug('Cache hit for LLM request', {
          requestId: normalizedRequest.requestId,
          model: normalizedRequest.model,
          userId: normalizedRequest.userId
        });
        
        return cachedResponse;
      }
    } catch (error) {
      // Don't fail the request if cache retrieval fails
      logger.warn('Error retrieving from LLM cache', {
        error: error instanceof Error ? error.message : String(error),
        requestId: normalizedRequest.requestId
      });
    }
    
    // Record the request in metrics
    this.metrics.recordRequest({
      provider: this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
      model: normalizedRequest.model,
      promptTokens: this.estimateTokens(
        normalizedRequest.messages.map(m => m.content || '').join('\n'),
        normalizedRequest.model
      ),
      maxTokens: normalizedRequest.maxTokens,
      temperature: normalizedRequest.temperature,
      stream: false,
      requestId: normalizedRequest.requestId,
      userId: normalizedRequest.userId
    });
    
    return this.executeWithRetry(async () => {
      const startTime = Date.now();
      
      try {
        // Apply rate limiting
        await this.applyRateLimit();
        
        // Get the provider for this model
        const provider = this.getProviderForModel(normalizedRequest.model);
        
        // Get the actual API key for the provider
        const providerEnum = this.getProviderEnum(provider.id);
        
        // Generate the text
        const response = await provider.generateText(normalizedRequest);
        const duration = Date.now() - startTime;
        
        // Record success metrics
        if (response.usage) {
          this.metrics.recordCompletion({
            provider: providerEnum,
            model: normalizedRequest.model,
            promptTokens: response.usage.promptTokens,
            completionTokens: response.usage.completionTokens,
            totalTokens: response.usage.totalTokens,
            durationMs: duration,
            success: true,
            requestId: normalizedRequest.requestId,
            userId: normalizedRequest.userId
          });
          
          // Update API key token usage for cost tracking
          const apiKey = this.tokenManager.getAPIKey(providerEnum);
          if (apiKey) {
            this.tokenManager.updateTokenUsage(
              providerEnum,
              apiKey,
              response.usage.promptTokens,
              response.usage.completionTokens
            );
          }
        }
        
        // Cache the response
        try {
          await this.cache.cacheTextResponse(normalizedRequest, response);
        } catch (cacheError) {
          logger.warn('Error caching LLM response', {
            error: cacheError instanceof Error ? cacheError.message : String(cacheError),
            requestId: normalizedRequest.requestId
          });
        }
        
        return response;
      } catch (error) {
        // Record error metrics
        this.metrics.recordError(
          this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
          normalizedRequest.model,
          error,
          normalizedRequest.requestId,
          normalizedRequest.userId
        );
        
        // Re-throw for retry mechanism
        throw error;
      }
    }, normalizedRequest);
  }

  /**
   * Generate a streaming text response
   * @param request - Text generation request
   * @returns Async generator of response chunks
   */
  public async *generateTextStream(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk> {
    // Force streaming mode
    request.stream = true;
    
    // Assign request ID if not provided
    if (!request.requestId) {
      request.requestId = uuidv4();
    }
    
    // Set default values if not provided
    const normalizedRequest = this.normalizeTextRequest(request);
    
    // Streaming requests cannot be cached, so proceed directly
    
    // Record the request in metrics
    this.metrics.recordRequest({
      provider: this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
      model: normalizedRequest.model,
      promptTokens: this.estimateTokens(
        normalizedRequest.messages.map(m => m.content || '').join('\n'),
        normalizedRequest.model
      ),
      maxTokens: normalizedRequest.maxTokens,
      temperature: normalizedRequest.temperature,
      stream: true,
      requestId: normalizedRequest.requestId,
      userId: normalizedRequest.userId
    });
    
    // Start time for tracking duration
    const startTime = Date.now();
    let promptTokens = 0;
    let completionTokens = 0;
    let success = false;
    let errorOccurred = false;
    let finalChunk: ILLMStreamChunk | null = null;
    
    try {
      // Apply rate limiting
      await this.applyRateLimit();
      
      // Get the provider for this model
      const provider = this.getProviderForModel(normalizedRequest.model);
      
      // Check if streaming is supported
      if (!provider.supportsStreaming(normalizedRequest.model)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Streaming is not supported for model ${normalizedRequest.model}`,
          true,
          'STREAMING_NOT_SUPPORTED'
        );
      }
      
      // Check if generateTextStream is implemented
      if (!provider.generateTextStream) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          `Provider ${provider.id} does not implement streaming`,
          true,
          'STREAMING_NOT_IMPLEMENTED'
        );
      }
      
      // Generate the streaming response
      const streamGenerator = provider.generateTextStream(normalizedRequest);
      
      for await (const chunk of streamGenerator) {
        // Track the final chunk for metrics
        if (chunk.isComplete) {
          finalChunk = chunk;
          success = true;
        }
        
        // Yield the chunk to the caller
        yield chunk;
      }
      
      // No final chunk received, create one
      if (!finalChunk) {
        finalChunk = {
          textDelta: '',
          text: '',
          isComplete: true,
          finishReason: 'stop'
        };
      }
      
      // Estimate token usage
      const fullText = finalChunk.text || '';
      promptTokens = this.estimateTokens(
        normalizedRequest.messages.map(m => m.content || '').join('\n'),
        normalizedRequest.model
      );
      completionTokens = this.estimateTokens(fullText, normalizedRequest.model);
    } catch (error) {
      errorOccurred = true;
      
      // Record error metrics
      this.metrics.recordError(
        this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
        normalizedRequest.model,
        error,
        normalizedRequest.requestId,
        normalizedRequest.userId
      );
      
      // Yield error chunk
      const errorChunk: ILLMStreamChunk = {
        textDelta: '',
        text: error instanceof Error ? error.message : String(error),
        isComplete: true,
        finishReason: 'error'
      };
      
      yield errorChunk;
      finalChunk = errorChunk;
    } finally {
      // Record completion metrics
      const duration = Date.now() - startTime;
      const totalTokens = promptTokens + completionTokens;
      
      // Only record completion metrics if we had a successful response
      if (!errorOccurred && finalChunk) {
        this.metrics.recordCompletion({
          provider: this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
          model: normalizedRequest.model,
          promptTokens,
          completionTokens,
          totalTokens,
          durationMs: duration,
          success,
          requestId: normalizedRequest.requestId,
          userId: normalizedRequest.userId
        });
        
        // Update API key token usage for cost tracking
        const providerEnum = this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id);
        const apiKey = this.tokenManager.getAPIKey(providerEnum);
        if (apiKey) {
          this.tokenManager.updateTokenUsage(
            providerEnum,
            apiKey,
            promptTokens,
            completionTokens
          );
        }
      }
    }
  }

  /**
   * Generate embeddings
   * @param request - Embedding request
   * @returns Embedding response
   */
  public async generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse> {
    // Assign request ID if not provided
    if (!request.requestId) {
      request.requestId = uuidv4();
    }
    
    // Set default values if not provided
    const normalizedRequest = this.normalizeEmbeddingRequest(request);
    
    // Try to get from cache first
    try {
      const cachedResponse = await this.cache.getCachedEmbeddingResponse(normalizedRequest);
      if (cachedResponse) {
        // Record cache hit in metrics
        this.metrics.recordCacheHit(
          this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
          normalizedRequest.model,
          cachedResponse.usage?.totalTokens || 0,
          normalizedRequest.requestId,
          normalizedRequest.userId
        );
        
        logger.debug('Cache hit for embedding request', {
          requestId: normalizedRequest.requestId,
          model: normalizedRequest.model,
          userId: normalizedRequest.userId
        });
        
        return cachedResponse;
      }
    } catch (error) {
      // Don't fail the request if cache retrieval fails
      logger.warn('Error retrieving from embedding cache', {
        error: error instanceof Error ? error.message : String(error),
        requestId: normalizedRequest.requestId
      });
    }
    
    // Calculate input tokens and count
    const inputTokens = Array.isArray(normalizedRequest.input)
      ? normalizedRequest.input.reduce(
          (sum, text) => sum + this.estimateTokens(text, normalizedRequest.model),
          0
        )
      : this.estimateTokens(normalizedRequest.input, normalizedRequest.model);
    
    const inputCount = Array.isArray(normalizedRequest.input)
      ? normalizedRequest.input.length
      : 1;
    
    return this.executeWithRetry(async () => {
      const startTime = Date.now();
      
      try {
        // Apply rate limiting
        await this.applyRateLimit();
        
        // Get the provider for this model
        const provider = this.getProviderForModel(normalizedRequest.model);
        
        // Generate the embeddings
        const response = await provider.generateEmbedding(normalizedRequest);
        const duration = Date.now() - startTime;
        
        // Record success metrics
        this.metrics.recordEmbedding({
          provider: this.getProviderEnum(provider.id),
          model: normalizedRequest.model,
          inputTokens,
          durationMs: duration,
          inputCount,
          dimensions: response.embeddings[0]?.length,
          success: true,
          requestId: normalizedRequest.requestId,
          userId: normalizedRequest.userId
        });
        
        // Update API key token usage for cost tracking
        const providerEnum = this.getProviderEnum(provider.id);
        const apiKey = this.tokenManager.getAPIKey(providerEnum);
        if (apiKey && response.usage) {
          this.tokenManager.updateTokenUsage(
            providerEnum,
            apiKey,
            response.usage.promptTokens,
            0 // No completion tokens for embeddings
          );
        }
        
        // Cache the response
        try {
          await this.cache.cacheEmbeddingResponse(normalizedRequest, response);
        } catch (cacheError) {
          logger.warn('Error caching embedding response', {
            error: cacheError instanceof Error ? cacheError.message : String(cacheError),
            requestId: normalizedRequest.requestId
          });
        }
        
        return response;
      } catch (error) {
        // Record error metrics
        this.metrics.recordError(
          this.getProviderEnum(this.getProviderForModel(normalizedRequest.model).id),
          normalizedRequest.model,
          error,
          normalizedRequest.requestId,
          normalizedRequest.userId
        );
        
        // Re-throw for retry mechanism
        throw error;
      }
    }, normalizedRequest);
  }

  /**
   * Get a provider by ID
   * @param provider - Provider enum value
   * @returns Provider instance
   */
  public getProvider(provider: LLMProvider): ILLMProvider {
    return this.providerFactory.getProvider(provider);
  }

  /**
   * Get the default provider
   * @returns Default provider instance
   */
  public getDefaultProvider(): ILLMProvider {
    return this.providerFactory.getProvider(
      config.ai.global.provider as LLMProvider
    );
  }

  /**
   * Check if a model is available with any provider
   * @param modelId - Model ID to check
   * @returns Boolean indicating availability
   */
  public isModelAvailable(modelId: string): boolean {
    for (const provider of this.providerFactory.getAllProviders()) {
      if (provider.supportsModel(modelId)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get the appropriate provider for a model
   * @param modelId - Model ID
   * @returns Provider that supports this model
   * @throws ApiError if no provider supports the model
   */
  public getProviderForModel(modelId: string): ILLMProvider {
    // Handle provider-specific prefixes
    if (modelId.startsWith('openai:') || modelId.startsWith('gpt-')) {
      return this.providerFactory.getProvider(LLMProvider.OPENAI);
    }
    
    if (modelId.startsWith('anthropic:') || modelId.startsWith('claude-')) {
      return this.providerFactory.getProvider(LLMProvider.ANTHROPIC);
    }
    
    if (modelId.startsWith('azure:')) {
      return this.providerFactory.getProvider(LLMProvider.AZURE_OPENAI);
    }
    
    // Check each provider
    for (const provider of this.providerFactory.getAllProviders()) {
      if (provider.supportsModel(modelId)) {
        return provider;
      }
    }
    
    // If no provider found, use default provider
    logger.warn(`No provider explicitly supports model ${modelId}, using default provider`);
    return this.getDefaultProvider();
  }

  /**
   * Get model context window information
   * @param modelId - Model ID
   * @returns Context window information
   */
  public getModelContext(modelId: string): IModelContextWindow {
    return this.getProviderForModel(modelId).getModelContext(modelId);
  }

  /**
   * Get model capabilities
   * @param modelId - Model ID
   * @returns Model capabilities
   */
  public getModelCapabilities(modelId: string): IModelCapabilities {
    return this.getProviderForModel(modelId).getModelCapabilities(modelId);
  }

  /**
   * Estimate token count for a text
   * @param text - Text to count tokens for
   * @param modelId - Optional model ID
   * @returns Estimated token count
   */
  public estimateTokens(text: string, modelId?: string): number {
    if (!text) return 0;
    
    if (modelId) {
      return this.getProviderForModel(modelId).estimateTokens(text, modelId);
    }
    
    // Use default provider if no model specified
    return this.getDefaultProvider().estimateTokens(text);
  }

  /**
   * Run a health check on all providers
   * @returns Health status object
   */
  public async healthCheck(): Promise<{
    overallStatus: 'healthy' | 'degraded' | 'unhealthy';
    providers: Record<string, boolean>;
  }> {
    const providers = this.providerFactory.getAllProviders();
    const results: Record<string, boolean> = {};
    let healthy = 0;
    let total = 0;
    
    // Check each provider
    for (const provider of providers) {
      total++;
      try {
        const isHealthy = await provider.healthCheck();
        results[provider.id] = isHealthy;
        if (isHealthy) healthy++;
      } catch (error) {
        logger.error(`Health check failed for provider ${provider.id}`, {
          error: error instanceof Error ? error.message : String(error)
        });
        results[provider.id] = false;
      }
    }
    
    // Check API key health
    const keyStats = this.tokenManager.getAPIKeyStats();
    
    // Determine overall status
    let overallStatus: 'healthy' | 'degraded' | 'unhealthy';
    if (healthy === total) {
      overallStatus = 'healthy';
    } else if (healthy === 0) {
      overallStatus = 'unhealthy';
    } else {
      overallStatus = 'degraded';
    }
    
    // If any provider has no active keys, downgrade status
    for (const providerStatus of Object.values(keyStats)) {
      if (providerStatus.activeKeys === 0) {
        overallStatus = overallStatus === 'healthy' ? 'degraded' : 'unhealthy';
        break;
      }
    }
    
    return {
      overallStatus,
      providers: results
    };
  }

  /**
   * Get metrics summary for a time period
   * @param startDate - Start date
   * @param endDate - End date
   * @returns Metrics summary
   */
  public async getMetricsSummary(startDate: Date, endDate: Date): Promise<any> {
    return this.metrics.getMetricsSummary(startDate, endDate);
  }

  /**
   * Convert provider ID to enum
   * @param providerId - Provider ID string
   * @returns Provider enum value
   */
  private getProviderEnum(providerId: string): LLMProvider {
    switch (providerId.toLowerCase()) {
      case 'openai':
        return LLMProvider.OPENAI;
      case 'anthropic':
        return LLMProvider.ANTHROPIC;
      case 'azureopenai':
        return LLMProvider.AZURE_OPENAI;
      default:
        return LLMProvider.OPENAI;
    }
  }

  /**
   * Apply rate limit with delay if needed
   */
  private async applyRateLimit(): Promise<void> {
    if (!this.rateLimiter.canMakeRequest()) {
      const delay = this.rateLimiter.getTimeUntilAvailable();
      logger.debug(`Rate limit hit, waiting ${delay}ms`);
      await setTimeout(delay);
    }
    this.rateLimiter.recordRequest();
  }

  /**
   * Normalize a text request with default values
   * @param request - Original request
   * @returns Normalized request
   */
  private normalizeTextRequest(request: ILLMTextRequest): ILLMTextRequest {
    return {
      ...request,
      temperature: request.temperature ?? 0,
      maxTokens: request.maxTokens ?? 1000,
      topP: request.topP ?? 1,
      frequencyPenalty: request.frequencyPenalty ?? 0,
      presencePenalty: request.presencePenalty ?? 0,
      timeoutMs: request.timeoutMs ?? 60000
    };
  }

  /**
   * Normalize an embedding request with default values
   * @param request - Original request
   * @returns Normalized request
   */
  private normalizeEmbeddingRequest(request: ILLMEmbeddingRequest): ILLMEmbeddingRequest {
    return {
      ...request,
      timeoutMs: request.timeoutMs ?? 60000
    };
  }

  /**
   * Execute a function with retry logic
   * @param fn - Function to execute
   * @param request - Original request (for logging)
   * @returns Result of the function
   */
  private async executeWithRetry<T, R extends { model: string, requestId?: string }>(
    fn: () => Promise<T>,
    request: R
  ): Promise<T> {
    const maxRetries = config.ai.global.maxRetries;
    const retryDelay = config.ai.global.retryDelayMs;
    
    let lastError: Error | undefined;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        // Execute the function
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        // Don't retry if this is the last attempt
        if (attempt === maxRetries) {
          break;
        }
        
        // Don't retry for certain error types
        if (error instanceof ApiError && [
          HTTP_STATUS.BAD_REQUEST,
          HTTP_STATUS.UNAUTHORIZED,
          HTTP_STATUS.FORBIDDEN,
          HTTP_STATUS.NOT_FOUND
        ].includes(error.statusCode)) {
          break;
        }
        
        // Log retry attempt
        logger.warn(`Retrying LLM request (${attempt + 1}/${maxRetries})`, {
          requestId: request.requestId,
          model: request.model,
          error: lastError.message
        });
        
        // Wait before retry (with exponential backoff)
        const delay = retryDelay * Math.pow(2, attempt);
        await setTimeout(delay);
      }
    }
    
    // If we get here, all retries failed
    throw lastError || new Error('Unknown error during LLM request');
  }
} 