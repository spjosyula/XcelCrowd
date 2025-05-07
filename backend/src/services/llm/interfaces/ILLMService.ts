import { 
  ILLMTextRequest, 
  ILLMTextResponse, 
  ILLMEmbeddingRequest, 
  ILLMEmbeddingResponse,
  ILLMStreamChunk
} from './ILLMRequest';
import { ILLMProvider, IModelCapabilities, IModelContextWindow } from './ILLMProvider';
import { LLMProvider } from '../../../config/llm.token.manager';

/**
 * Interface for the LLM service - the main entry point for all LLM operations
 */
export interface ILLMService {
  /**
   * Generate text using the specified or default LLM provider
   * @param request - The text generation request
   * @returns A promise resolving to the text response
   */
  generateText(request: ILLMTextRequest): Promise<ILLMTextResponse>;
  
  /**
   * Generate text stream using the specified or default LLM provider
   * @param request - The text generation request
   * @returns An async generator yielding stream chunks
   */
  generateTextStream(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk>;
  
  /**
   * Generate embeddings using the specified or default LLM provider
   * @param request - The embedding request
   * @returns A promise resolving to the embedding response
   */
  generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse>;
  
  /**
   * Get a specific LLM provider instance
   * @param provider - The provider to get
   * @returns The provider instance
   */
  getProvider(provider: LLMProvider): ILLMProvider;
  
  /**
   * Get the default LLM provider instance
   * @returns The default provider instance
   */
  getDefaultProvider(): ILLMProvider;
  
  /**
   * Check if a model is available with any provider
   * @param modelId - The model ID to check
   * @returns Boolean indicating if the model is available
   */
  isModelAvailable(modelId: string): boolean;
  
  /**
   * Get the appropriate provider for a model
   * @param modelId - The model ID
   * @returns The provider that supports this model
   */
  getProviderForModel(modelId: string): ILLMProvider;
  
  /**
   * Get model context window information
   * @param modelId - The model ID
   * @returns The context window information
   */
  getModelContext(modelId: string): IModelContextWindow;
  
  /**
   * Get model capabilities
   * @param modelId - The model ID
   * @returns The model capabilities
   */
  getModelCapabilities(modelId: string): IModelCapabilities;
  
  /**
   * Estimate token count for a string
   * @param text - The text to count tokens for
   * @param modelId - Optional model ID for model-specific counting
   * @returns Estimated token count
   */
  estimateTokens(text: string, modelId?: string): number;
  
  /**
   * Run a health check on all providers
   * @returns A promise resolving to a health status object
   */
  healthCheck(): Promise<{
    overallStatus: 'healthy' | 'degraded' | 'unhealthy';
    providers: Record<string, boolean>;
  }>;
  
  /**
   * Get metrics summary for LLM usage
   * @param startDate - Start date for metrics
   * @param endDate - End date for metrics
   * @returns A promise resolving to a metrics summary
   */
  getMetricsSummary(startDate: Date, endDate: Date): Promise<any>;
} 