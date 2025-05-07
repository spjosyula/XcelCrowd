import { logger } from '../../utils/logger';
import { ILLMTextRequest, ILLMTextResponse, ILLMEmbeddingRequest, ILLMEmbeddingResponse } from './interfaces/ILLMRequest';
import { createHash } from 'crypto';
import { config } from '../../config/config.env.validation';
import NodeCache from 'node-cache';
import mongoose from 'mongoose';

/**
 * Enum of available cache storage strategies
 */
export enum CacheStorageStrategy {
  MEMORY = 'memory',
  DATABASE = 'database'
}

/**
 * Interface for cache options
 */
export interface ICacheOptions {
  /**
   * Whether caching is enabled
   */
  enabled: boolean;
  
  /**
   * TTL in seconds for cached items
   */
  ttl: number;
  
  /**
   * Maximum size of cache items to store (bytes for memory, count for DB)
   */
  maxSize?: number;
  
  /**
   * Storage strategy to use
   */
  strategy: CacheStorageStrategy;
  
  /**
   * Whether to check response similarity for cache hits
   */
  checkSimilarity?: boolean;
  
  /**
   * Similarity threshold for considering a cache hit (0-1)
   */
  similarityThreshold?: number;
}

/**
 * Cache key components
 */
interface ICacheKeyParams {
  model: string;
  messages?: string;
  functions?: string;
  input?: string;
}

/**
 * Response types that can be cached
 */
type CacheableResponse = ILLMTextResponse | ILLMEmbeddingResponse;

/**
 * Schema for database cache storage
 */
const LLMCacheSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    index: true
  },
  response: {
    type: Object,
    required: true
  },
  model: {
    type: String,
    required: true,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: config.ai.global.cacheTTLSeconds // TTL index
  },
  tokenCount: {
    type: Number
  },
  userId: {
    type: String,
    index: true
  },
  metadata: {
    type: Object
  }
});

/**
 * Enterprise-grade LLM response caching service
 * Improves performance and reduces costs by caching identical requests
 */
export class LLMCache {
  private static instance: LLMCache;
  private options: ICacheOptions;
  private memoryCache: NodeCache;
  private dbModel!: mongoose.Model<any>;
  
  /**
   * Private constructor for singleton pattern
   */
  private constructor() {
    // Initialize with default options
    this.options = {
      enabled: config.ai.global.cacheEnabled,
      ttl: config.ai.global.cacheTTLSeconds,
      strategy: CacheStorageStrategy.MEMORY
    };
    
    // Initialize memory cache
    this.memoryCache = new NodeCache({
      stdTTL: this.options.ttl,
      checkperiod: Math.floor(this.options.ttl / 10), // Check 10 times during TTL period
      useClones: false // For better performance with complex objects
    });
    
    // Initialize DB model if needed
    if (mongoose.connection.readyState === 1) {
      this.dbModel = mongoose.model('LLMCache', LLMCacheSchema);
    }
    
    // Log initialization
    logger.info('LLM cache initialized', {
      enabled: this.options.enabled,
      ttl: this.options.ttl,
      strategy: this.options.strategy
    });
  }
  
  /**
   * Get singleton instance
   */
  public static getInstance(): LLMCache {
    if (!LLMCache.instance) {
      LLMCache.instance = new LLMCache();
    }
    return LLMCache.instance;
  }
  
  /**
   * Configure the cache
   * @param options - Cache configuration options
   */
  public configure(options: Partial<ICacheOptions>): void {
    this.options = {
      ...this.options,
      ...options
    };
    
    // Update memory cache TTL if changed
    if (options.ttl !== undefined) {
      this.memoryCache.options.stdTTL = options.ttl;
      this.memoryCache.options.checkperiod = Math.floor(options.ttl / 10);
    }
    
    // Initialize DB model if strategy changed to database
    if (options.strategy === CacheStorageStrategy.DATABASE && !this.dbModel && mongoose.connection.readyState === 1) {
      this.dbModel = mongoose.model('LLMCache', LLMCacheSchema);
    }
    
    logger.info('LLM cache reconfigured', {
      enabled: this.options.enabled,
      ttl: this.options.ttl,
      strategy: this.options.strategy
    });
  }
  
  /**
   * Get cache key for a text request
   * @param request - Text generation request
   * @returns Cache key string
   */
  private getCacheKeyForTextRequest(request: ILLMTextRequest): string {
    // Extract key components
    const keyParams: ICacheKeyParams = {
      model: request.model,
      // Normalize messages to eliminate formatting differences
      messages: JSON.stringify(
        request.messages.map(m => ({
          role: m.role,
          content: m.content,
          name: m.name,
          functionCall: m.functionCall
        }))
      )
    };
    
    // Add function definitions if present
    if (request.functions && request.functions.length > 0) {
      keyParams.functions = JSON.stringify(request.functions);
    }
    
    // Create hash for the key
    return this.createCacheKey(keyParams);
  }
  
  /**
   * Get cache key for an embedding request
   * @param request - Embedding request
   * @returns Cache key string
   */
  private getCacheKeyForEmbeddingRequest(request: ILLMEmbeddingRequest): string {
    // Extract key components
    const keyParams: ICacheKeyParams = {
      model: request.model,
      // Handle both string and array inputs
      input: typeof request.input === 'string' 
        ? request.input 
        : JSON.stringify(request.input)
    };
    
    // Create hash for the key
    return this.createCacheKey(keyParams);
  }
  
  /**
   * Create a deterministic cache key hash
   * @param params - Key parameters
   * @returns Hash string
   */
  private createCacheKey(params: ICacheKeyParams): string {
    const serialized = JSON.stringify(params);
    return createHash('sha256').update(serialized).digest('hex');
  }
  
  /**
   * Get cached text response
   * @param request - Text generation request
   * @returns Cached response or null if not found
   */
  public async getCachedTextResponse(request: ILLMTextRequest): Promise<ILLMTextResponse | null> {
    if (!this.options.enabled) return null;
    
    // Don't cache streaming requests
    if (request.stream) return null;
    
    // Don't cache requests with specific temperature/seed settings
    // that are likely to produce different results
    if (request.seed !== undefined || request.temperature !== undefined && request.temperature > 0.1) {
      return null;
    }
    
    const cacheKey = this.getCacheKeyForTextRequest(request);
    
    try {
      if (this.options.strategy === CacheStorageStrategy.MEMORY) {
        return this.memoryCache.get<ILLMTextResponse>(cacheKey) || null;
      } else {
        const cached = await this.dbModel.findOne({ key: cacheKey }).lean();
        return cached && typeof cached === 'object' && 'response' in cached
          ? (cached.response as ILLMTextResponse)
          : null;
      }
    } catch (error) {
      logger.warn('Error retrieving from LLM cache', {
        error: error instanceof Error ? error.message : String(error),
        cacheKey
      });
      return null;
    }
  }
  
  /**
   * Get cached embedding response
   * @param request - Embedding request
   * @returns Cached response or null if not found
   */
  public async getCachedEmbeddingResponse(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse | null> {
    if (!this.options.enabled) return null;
    
    const cacheKey = this.getCacheKeyForEmbeddingRequest(request);
    
    try {
      if (this.options.strategy === CacheStorageStrategy.MEMORY) {
        return this.memoryCache.get<ILLMEmbeddingResponse>(cacheKey) || null;
      } else {
        const cached: any = await this.dbModel.findOne({ key: cacheKey }).lean();
        return cached && typeof cached === 'object' && 'response' in cached
          ? (cached.response as ILLMEmbeddingResponse)
          : null;
      }
    } catch (error) {
      logger.warn('Error retrieving embeddings from LLM cache', {
        error: error instanceof Error ? error.message : String(error),
        cacheKey
      });
      return null;
    }
  }
  
  /**
   * Cache a text response
   * @param request - Original request
   * @param response - Response to cache
   */
  public async cacheTextResponse(request: ILLMTextRequest, response: ILLMTextResponse): Promise<void> {
    if (!this.options.enabled) return;
    
    // Don't cache streaming requests
    if (request.stream) return;
    
    // Don't cache incomplete or error responses
    if (!response.text || response.finishReason === 'error') return;
    
    const cacheKey = this.getCacheKeyForTextRequest(request);
    
    try {
      if (this.options.strategy === CacheStorageStrategy.MEMORY) {
        this.memoryCache.set(cacheKey, response, this.options.ttl);
      } else {
        // Store in database
        await this.dbModel.updateOne(
          { key: cacheKey },
          {
            $set: {
              response,
              model: request.model,
              tokenCount: response.usage?.totalTokens,
              userId: request.userId,
              metadata: request.metadata
            }
          },
          { upsert: true }
        );
      }
      
      logger.debug('Cached LLM text response', {
        cacheKey,
        model: request.model,
        tokenCount: response.usage?.totalTokens,
        strategy: this.options.strategy
      });
    } catch (error) {
      logger.warn('Error caching LLM response', {
        error: error instanceof Error ? error.message : String(error),
        cacheKey
      });
    }
  }
  
  /**
   * Cache an embedding response
   * @param request - Original request
   * @param response - Response to cache
   */
  public async cacheEmbeddingResponse(request: ILLMEmbeddingRequest, response: ILLMEmbeddingResponse): Promise<void> {
    if (!this.options.enabled) return;
    
    const cacheKey = this.getCacheKeyForEmbeddingRequest(request);
    
    try {
      if (this.options.strategy === CacheStorageStrategy.MEMORY) {
        this.memoryCache.set(cacheKey, response, this.options.ttl);
      } else {
        // Store in database
        await this.dbModel.updateOne(
          { key: cacheKey },
          {
            $set: {
              response,
              model: request.model,
              tokenCount: response.usage?.totalTokens,
              userId: request.userId,
              metadata: request.metadata
            }
          },
          { upsert: true }
        );
      }
      
      logger.debug('Cached LLM embedding response', {
        cacheKey,
        model: request.model,
        tokenCount: response.usage?.totalTokens,
        inputLength: typeof request.input === 'string' ? 1 : request.input.length,
        strategy: this.options.strategy
      });
    } catch (error) {
      logger.warn('Error caching LLM embedding response', {
        error: error instanceof Error ? error.message : String(error),
        cacheKey
      });
    }
  }
  
  /**
   * Clear all cached items
   */
  public async clearCache(): Promise<void> {
    try {
      if (this.options.strategy === CacheStorageStrategy.MEMORY) {
        this.memoryCache.flushAll();
      } else {
        if (this.dbModel) {
          await this.dbModel.deleteMany({});
        }
      }
      
      logger.info('LLM cache cleared', {
        strategy: this.options.strategy
      });
    } catch (error) {
      logger.error('Error clearing LLM cache', {
        error: error instanceof Error ? error.message : String(error),
        strategy: this.options.strategy
      });
    }
  }
  
  /**
   * Get cache statistics
   */
  public async getCacheStats(): Promise<{
    strategy: CacheStorageStrategy;
    enabled: boolean;
    ttl: number;
    size: number;
    hits: number;
    misses: number;
    hitRate: number;
  }> {
    if (this.options.strategy === CacheStorageStrategy.MEMORY) {
      const stats = this.memoryCache.getStats();
      
      return {
        strategy: this.options.strategy,
        enabled: this.options.enabled,
        ttl: this.options.ttl,
        size: this.memoryCache.keys().length,
        hits: stats.hits,
        misses: stats.misses,
        hitRate: stats.hits / (stats.hits + stats.misses || 1)
      };
    } else {
      // For database strategy
      const size = await this.dbModel.countDocuments();
      
      // We don't have built-in hit/miss tracking for DB
      // This would need a separate metrics collection
      return {
        strategy: this.options.strategy,
        enabled: this.options.enabled,
        ttl: this.options.ttl,
        size,
        hits: 0, // Would need separate tracking
        misses: 0, // Would need separate tracking
        hitRate: 0 // Would need separate tracking
      };
    }
  }
  
  /**
   * Clean up resources
   */
  public cleanup(): void {
    if (this.options.strategy === CacheStorageStrategy.MEMORY) {
      this.memoryCache.close();
    }
    
    logger.debug('LLM cache cleaned up');
  }
} 