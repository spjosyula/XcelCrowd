import { logger } from '../../../utils/logger';
import { LLMProvider } from '../../../config/llm.token.manager';
import { singleton } from 'tsyringe';
import mongoose from 'mongoose';
import EventEmitter from 'events';

/**
 * Metric types for LLM API calls
 */
export enum MetricType {
  REQUEST = 'request',
  COMPLETION = 'completion',
  EMBEDDING = 'embedding',
  ERROR = 'error',
  CACHE_HIT = 'cache_hit',
  LATENCY = 'latency',
  TOKEN_USAGE = 'token_usage',
  COST = 'cost'
}

/**
 * Common metric fields
 */
interface IBaseMetric {
  timestamp: Date;
  provider: LLMProvider;
  model: string;
  userId?: string;
  requestId?: string;
}

/**
 * Request metric data
 */
export interface IRequestMetric extends IBaseMetric {
  type: MetricType.REQUEST;
  promptTokens: number;
  maxTokens?: number;
  temperature?: number;
  stream: boolean;
}

/**
 * Completion metric data
 */
export interface ICompletionMetric extends IBaseMetric {
  type: MetricType.COMPLETION;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  durationMs: number;
  success: boolean;
}

/**
 * Embedding metric data
 */
export interface IEmbeddingMetric extends IBaseMetric {
  type: MetricType.EMBEDDING;
  inputTokens: number;
  durationMs: number;
  inputCount: number;
  dimensions?: number;
  success: boolean;
}

/**
 * Error metric data
 */
export interface IErrorMetric extends IBaseMetric {
  type: MetricType.ERROR;
  errorType: string;
  errorMessage: string;
  statusCode?: number;
}

/**
 * Cache hit metric data
 */
export interface ICacheHitMetric extends IBaseMetric {
  type: MetricType.CACHE_HIT;
  tokensServed: number;
}

/**
 * Combined metric type
 */
export type Metric = 
  | IRequestMetric 
  | ICompletionMetric 
  | IEmbeddingMetric 
  | IErrorMetric 
  | ICacheHitMetric;

/**
 * Schema for database metrics storage
 */
const LLMMetricSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  type: {
    type: String,
    enum: Object.values(MetricType),
    required: true,
    index: true
  },
  provider: {
    type: String,
    enum: Object.values(LLMProvider),
    required: true,
    index: true
  },
  model: {
    type: String,
    required: true,
    index: true
  },
  userId: {
    type: String,
    index: true
  },
  requestId: {
    type: String,
    index: true
  },
  // Request specific
  promptTokens: Number,
  maxTokens: Number,
  temperature: Number,
  stream: Boolean,
  // Completion specific
  completionTokens: Number,
  totalTokens: Number,
  durationMs: Number,
  success: Boolean,
  // Embedding specific
  inputTokens: Number,
  inputCount: Number,
  dimensions: Number,
  // Error specific
  errorType: String,
  errorMessage: String,
  statusCode: Number,
  // Cache specific
  tokensServed: Number,
}, {
  capped: { size: 100 * 1024 * 1024, max: 1000000 } // 100MB or 1M documents
});

/**
 * Enterprise-grade metrics collection for LLM API calls
 * Tracks performance, cost, and usage
 */
@singleton()
export class LLMMetricsCollector extends EventEmitter {
  private static instance: LLMMetricsCollector;
  private metricsModel: mongoose.Model<any> | null = null;
  private inMemoryMetrics: Metric[] = [];
  private readonly MAX_IN_MEMORY_METRICS = 1000;
  private flushInterval: NodeJS.Timeout | null = null;
  private isDbEnabled: boolean = false;
  
  /**
   * Constructor
   */
  constructor() {
    super();
    
    // Try to initialize the database model
    this.initializeModel();
    
    // Set up automatic flushing of in-memory metrics
    this.flushInterval = setInterval(() => this.flushMetrics(), 60000); // Every minute
    
    logger.info('LLM metrics collector initialized', {
      dbEnabled: this.isDbEnabled
    });
  }
  
  /**
   * Get singleton instance
   */
  public static getInstance(): LLMMetricsCollector {
    if (!LLMMetricsCollector.instance) {
      LLMMetricsCollector.instance = new LLMMetricsCollector();
    }
    return LLMMetricsCollector.instance;
  }
  
  /**
   * Initialize the database model
   */
  private initializeModel(): void {
    try {
      if (mongoose.connection.readyState === 1) {
        if (!mongoose.models.LLMMetric) {
          this.metricsModel = mongoose.model('LLMMetric', LLMMetricSchema);
        } else {
          this.metricsModel = mongoose.models.LLMMetric;
        }
        this.isDbEnabled = true;
        logger.debug('LLM metrics database model initialized');
      } else {
        logger.warn('MongoDB not connected, using in-memory metrics only');
        this.isDbEnabled = false;
      }
    } catch (error) {
      logger.error('Failed to initialize LLM metrics database model', {
        error: error instanceof Error ? error.message : String(error)
      });
      this.isDbEnabled = false;
    }
  }
  
  /**
   * Record a request metric
   * @param metric - Request metric data
   */
  public recordRequest(metric: Omit<IRequestMetric, 'type' | 'timestamp'>): void {
    const fullMetric: IRequestMetric = {
      ...metric,
      type: MetricType.REQUEST,
      timestamp: new Date()
    };
    
    this.recordMetric(fullMetric);
    this.emit('request', fullMetric);
  }
  
  /**
   * Record a completion metric
   * @param metric - Completion metric data
   */
  public recordCompletion(metric: Omit<ICompletionMetric, 'type' | 'timestamp'>): void {
    const fullMetric: ICompletionMetric = {
      ...metric,
      type: MetricType.COMPLETION,
      timestamp: new Date()
    };
    
    this.recordMetric(fullMetric);
    this.emit('completion', fullMetric);
    
    // Also calculate and emit a cost metric
    this.calculateAndEmitCost(fullMetric);
  }
  
  /**
   * Record an embedding metric
   * @param metric - Embedding metric data
   */
  public recordEmbedding(metric: Omit<IEmbeddingMetric, 'type' | 'timestamp'>): void {
    const fullMetric: IEmbeddingMetric = {
      ...metric,
      type: MetricType.EMBEDDING,
      timestamp: new Date()
    };
    
    this.recordMetric(fullMetric);
    this.emit('embedding', fullMetric);
  }
  
  /**
   * Record an error metric
   * @param provider - LLM provider
   * @param model - Model name
   * @param error - Error object
   * @param requestId - Optional request ID
   * @param userId - Optional user ID
   */
  public recordError(
    provider: LLMProvider,
    model: string,
    error: any,
    requestId?: string,
    userId?: string
  ): void {
    // Determine error type
    let errorType = 'UNKNOWN';
    let statusCode: number | undefined = undefined;
    
    if (error.response) {
      statusCode = error.response.status;
      errorType = `HTTP_${statusCode}`;
      
      if (statusCode === 429) errorType = 'RATE_LIMIT';
      else if (typeof statusCode === 'number' && statusCode >= 500) errorType = 'SERVER_ERROR';
      else if (typeof statusCode === 'number' && statusCode >= 400) errorType = 'CLIENT_ERROR';
    } else if (error.code === 'ECONNABORTED') {
      errorType = 'TIMEOUT';
    } else if (error.code === 'ECONNREFUSED') {
      errorType = 'CONNECTION_REFUSED';
    } else if (error instanceof Error) {
      if (error.message.includes('timeout')) errorType = 'TIMEOUT';
      else if (error.message.includes('abort')) errorType = 'ABORTED';
    }
    
    const metric: IErrorMetric = {
      type: MetricType.ERROR,
      timestamp: new Date(),
      provider,
      model,
      errorType,
      errorMessage: error instanceof Error ? error.message : String(error),
      statusCode,
      requestId,
      userId
    };
    
    this.recordMetric(metric);
    this.emit('error', metric);
  }
  
  /**
   * Record a cache hit metric
   * @param provider - LLM provider
   * @param model - Model name
   * @param tokensServed - Number of tokens served from cache
   * @param requestId - Optional request ID
   * @param userId - Optional user ID
   */
  public recordCacheHit(
    provider: LLMProvider,
    model: string,
    tokensServed: number,
    requestId?: string,
    userId?: string
  ): void {
    const metric: ICacheHitMetric = {
      type: MetricType.CACHE_HIT,
      timestamp: new Date(),
      provider,
      model,
      tokensServed,
      requestId,
      userId
    };
    
    this.recordMetric(metric);
    this.emit('cacheHit', metric);
  }
  
  /**
   * Calculate and emit a cost metric from a completion metric
   * @param metric - Completion metric
   */
  private calculateAndEmitCost(metric: ICompletionMetric): void {
    const cost = this.calculateCost(
      metric.provider, 
      metric.model,
      metric.promptTokens,
      metric.completionTokens
    );
    
    this.emit('cost', {
      timestamp: metric.timestamp,
      type: MetricType.COST,
      provider: metric.provider,
      model: metric.model,
      cost,
      promptTokens: metric.promptTokens,
      completionTokens: metric.completionTokens,
      totalTokens: metric.totalTokens,
      userId: metric.userId,
      requestId: metric.requestId
    });
  }
  
  /**
   * Calculate estimated cost of token usage
   * @param provider - LLM provider
   * @param model - Model name
   * @param promptTokens - Number of prompt tokens
   * @param completionTokens - Number of completion tokens
   * @returns Estimated cost in USD
   */
  private calculateCost(
    provider: LLMProvider,
    model: string,
    promptTokens: number,
    completionTokens: number
  ): number {
    // These are simplified cost estimates, actual costs would depend on model details
    // A complete implementation would use a lookup table for specific model pricing
    
    // Default prices
    let promptPrice = 0.00001; // $0.01 per 1000 tokens
    let completionPrice = 0.00002; // $0.02 per 1000 tokens
    
    // Set pricing based on provider and model
    switch (provider) {
      case LLMProvider.OPENAI:
        if (model.includes('gpt-4')) {
          promptPrice = 0.00003; // $0.03 per 1000 tokens
          completionPrice = 0.00006; // $0.06 per 1000 tokens
        } else if (model.includes('gpt-3.5')) {
          promptPrice = 0.000001; // $0.001 per 1000 tokens
          completionPrice = 0.000002; // $0.002 per 1000 tokens
        }
        break;
        
      case LLMProvider.ANTHROPIC:
        if (model.includes('claude-3-opus')) {
          promptPrice = 0.00008; // $0.08 per 1000 tokens
          completionPrice = 0.00024; // $0.24 per 1000 tokens
        } else if (model.includes('claude-3-sonnet')) {
          promptPrice = 0.000003; // $0.003 per 1000 tokens
          completionPrice = 0.000015; // $0.015 per 1000 tokens
        } else if (model.includes('claude-3-haiku')) {
          promptPrice = 0.00000025; // $0.00025 per 1000 tokens
          completionPrice = 0.00000125; // $0.00125 per 1000 tokens
        }
        break;
        
      case LLMProvider.AZURE_OPENAI:
        // Use same pricing as OpenAI
        if (model.includes('gpt-4')) {
          promptPrice = 0.00003; // $0.03 per 1000 tokens
          completionPrice = 0.00006; // $0.06 per 1000 tokens
        } else if (model.includes('gpt-3.5')) {
          promptPrice = 0.000001; // $0.001 per 1000 tokens
          completionPrice = 0.000002; // $0.002 per 1000 tokens
        }
        break;
    }
    
    return (promptTokens * promptPrice) + (completionTokens * completionPrice);
  }
  
  /**
   * General method to record a metric
   * @param metric - The metric to record
   */
  private recordMetric(metric: Metric): void {
    // Store in memory
    this.inMemoryMetrics.push(metric);
    
    // Flush if we've reached the limit
    if (this.inMemoryMetrics.length >= this.MAX_IN_MEMORY_METRICS) {
      this.flushMetrics();
    }
    
    // Also store in database if enabled
    if (this.isDbEnabled && this.metricsModel) {
      this.metricsModel.create(metric).catch(error => {
        logger.error('Failed to store LLM metric in database', {
          error: error instanceof Error ? error.message : String(error),
          metricType: metric.type
        });
      });
    }
  }
  
  /**
   * Flush in-memory metrics (e.g., write to DB or external service)
   */
  private flushMetrics(): void {
    if (this.inMemoryMetrics.length === 0) return;
    
    // In a production system, we might send these metrics to an external
    // monitoring service like Prometheus, Datadog, or CloudWatch
    
    // For now, we'll just log a summary
    const summary = this.summarizeMetrics(this.inMemoryMetrics);
    
    logger.info('LLM metrics summary', { summary });
    
    // Clear the in-memory metrics
    this.inMemoryMetrics = [];
  }
  
  /**
   * Summarize metrics for reporting
   * @param metrics - Array of metrics to summarize
   * @returns Summary object
   */
  private summarizeMetrics(metrics: Metric[]): Record<string, any> {
    const summary: Record<string, any> = {
      total: metrics.length,
      byType: {},
      byProvider: {},
      byModel: {},
      totalTokens: 0,
      averageLatency: 0
    };
    
    // Count by type
    for (const type of Object.values(MetricType)) {
      summary.byType[type] = metrics.filter(m => m.type === type).length;
    }
    
    // Count by provider
    for (const provider of Object.values(LLMProvider)) {
      summary.byProvider[provider] = metrics.filter(m => m.provider === provider).length;
    }
    
    // Count by model
    const models = [...new Set(metrics.map(m => m.model))];
    for (const model of models) {
      summary.byModel[model] = metrics.filter(m => m.model === model).length;
    }
    
    // Calculate total tokens
    let tokenCount = 0;
    let latencySum = 0;
    let latencyCount = 0;
    
    for (const metric of metrics) {
      if (metric.type === MetricType.COMPLETION) {
        tokenCount += metric.totalTokens;
        latencySum += metric.durationMs;
        latencyCount++;
      } else if (metric.type === MetricType.EMBEDDING) {
        tokenCount += metric.inputTokens;
        latencySum += metric.durationMs;
        latencyCount++;
      }
    }
    
    summary.totalTokens = tokenCount;
    summary.averageLatency = latencyCount > 0 ? latencySum / latencyCount : 0;
    
    return summary;
  }
  
  /**
   * Get metrics for analysis
   * @param filter - Filter criteria
   * @param limit - Maximum number of results
   * @returns Array of metrics
   */
  public async getMetrics(
    filter: {
      startDate?: Date;
      endDate?: Date;
      type?: MetricType;
      provider?: LLMProvider;
      model?: string;
      userId?: string;
    } = {},
    limit = 1000
  ): Promise<Metric[]> {
    if (!this.isDbEnabled || !this.metricsModel) {
      return this.inMemoryMetrics.filter(m => {
        // Apply filters
        if (filter.type && m.type !== filter.type) return false;
        if (filter.provider && m.provider !== filter.provider) return false;
        if (filter.model && m.model !== filter.model) return false;
        if (filter.userId && m.userId !== filter.userId) return false;
        if (filter.startDate && m.timestamp < filter.startDate) return false;
        if (filter.endDate && m.timestamp > filter.endDate) return false;
        return true;
      }).slice(0, limit);
    }
    
    // Build database query
    const query: Record<string, any> = {};
    
    if (filter.type) query.type = filter.type;
    if (filter.provider) query.provider = filter.provider;
    if (filter.model) query.model = filter.model;
    if (filter.userId) query.userId = filter.userId;
    
    if (filter.startDate || filter.endDate) {
      query.timestamp = {};
      if (filter.startDate) query.timestamp.$gte = filter.startDate;
      if (filter.endDate) query.timestamp.$lte = filter.endDate;
    }
    
    try {
      const results = await this.metricsModel.find(query).sort({ timestamp: -1 }).limit(limit).lean();
      
      // Transform the results to match the Metric type
      return results.map(result => {
        // Remove MongoDB specific fields
        const { _id, __v, ...metricData } = result;
        return metricData as Metric;
      });
    } catch (error) {
      logger.error('Failed to retrieve LLM metrics from database', {
        error: error instanceof Error ? error.message : String(error)
      });
      return [];
    }
  }
  
  /**
   * Get metrics summary for a time period
   * @param startDate - Start date
   * @param endDate - End date
   * @returns Summary object
   */
  public async getMetricsSummary(
    startDate: Date,
    endDate: Date
  ): Promise<{
    requestCount: number;
    totalTokens: number;
    averageLatency: number;
    errorRate: number;
    cacheHitRate: number;
    estimatedCost: number;
    byProvider: Record<string, number>;
    byModel: Record<string, number>;
  }> {
    const metrics = await this.getMetrics({ startDate, endDate }, 10000);
    
    // Calculate summary statistics
    const requestCount = metrics.filter(m => m.type === MetricType.REQUEST).length;
    const completions = metrics.filter(m => m.type === MetricType.COMPLETION) as ICompletionMetric[];
    const errors = metrics.filter(m => m.type === MetricType.ERROR).length;
    const cacheHits = metrics.filter(m => m.type === MetricType.CACHE_HIT).length;
    
    // Group by provider and model
    const byProvider: Record<string, number> = {};
    const byModel: Record<string, number> = {};
    
    for (const metric of metrics) {
      byProvider[metric.provider] = (byProvider[metric.provider] || 0) + 1;
      byModel[metric.model] = (byModel[metric.model] || 0) + 1;
    }
    
    // Calculate token usage and cost
    let totalTokens = 0;
    let latencySum = 0;
    let estimatedCost = 0;
    
    for (const completion of completions) {
      totalTokens += completion.totalTokens;
      latencySum += completion.durationMs;
      
      // Calculate cost
      estimatedCost += this.calculateCost(
        completion.provider,
        completion.model,
        completion.promptTokens,
        completion.completionTokens
      );
    }
    
    return {
      requestCount,
      totalTokens,
      averageLatency: completions.length > 0 ? latencySum / completions.length : 0,
      errorRate: requestCount > 0 ? errors / requestCount : 0,
      cacheHitRate: (requestCount + cacheHits) > 0 ? cacheHits / (requestCount + cacheHits) : 0,
      estimatedCost,
      byProvider,
      byModel
    };
  }
  
  /**
   * Clean up resources
   */
  public cleanup(): void {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    
    // Final flush of metrics
    this.flushMetrics();
    
    logger.debug('LLM metrics collector cleaned up');
  }
} 