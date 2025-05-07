import { ILLMTextRequest, ILLMTextResponse, ILLMEmbeddingRequest, ILLMEmbeddingResponse, ILLMStreamChunk } from './ILLMRequest';

/**
 * Represents the context window size for a model
 */
export interface IModelContextWindow {
  maxInputTokens: number;
  maxTotalTokens: number;
}

/**
 * Represents capabilities of a language model
 */
export interface IModelCapabilities {
  supportsStreaming: boolean;
  supportsJsonMode: boolean;
  supportsFunctionCalling: boolean;
  supportsVision: boolean;
  maxFunctions?: number;
}

/**
 * Model pricing information for cost estimation
 */
export interface IModelPricing {
  inputPerTokenCost: number;
  outputPerTokenCost: number;
  currency: string;
}

/**
 * Interface defining a standardized LLM provider
 * All LLM providers must implement this interface to ensure consistency
 */
export interface ILLMProvider {
  /**
   * Unique identifier for the provider
   */
  id: string;
  
  /**
   * Display name of the provider
   */
  name: string;
  
  /**
   * List of available models for this provider
   */
  models: string[];
  
  /**
   * Check if a model is available for this provider
   * @param modelId - The model ID to check
   */
  supportsModel(modelId: string): boolean;
  
  /**
   * Generate text from the LLM
   * @param request - The text generation request
   * @returns A promise resolving to the text response
   */
  generateText(request: ILLMTextRequest): Promise<ILLMTextResponse>;
  
  /**
   * Generate text embeddings
   * @param request - The embedding request
   * @returns A promise resolving to the embedding response
   */
  generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse>;
  
  /**
   * Check if streaming is supported for a specific model
   * @param modelId - The model ID to check
   * @returns Boolean indicating support for streaming
   */
  supportsStreaming(modelId: string): boolean;
  
  /**
   * Generate streaming text from the LLM
   * @param request - The text generation request
   * @returns An async generator yielding stream chunks
   * @throws Error if streaming is not supported
   */
  generateTextStream?(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk>;
  
  /**
   * Get model context window size
   * @param modelId - The model ID
   * @returns Context window information
   */
  getModelContext(modelId: string): IModelContextWindow;
  
  /**
   * Get model capabilities
   * @param modelId - The model ID
   * @returns Model capabilities
   */
  getModelCapabilities(modelId: string): IModelCapabilities;
  
  /**
   * Get model pricing information
   * @param modelId - The model ID
   * @returns Pricing information
   */
  getModelPricing(modelId: string): IModelPricing;
  
  /**
   * Estimate token count for a string
   * @param text - The text to count tokens for
   * @param modelId - Optional model ID for model-specific counting
   * @returns Estimated token count
   */
  estimateTokens(text: string, modelId?: string): number;
  
  /**
   * Health check for the provider
   * @returns A promise resolving to a boolean indicating if the provider is healthy
   */
  healthCheck(): Promise<boolean>;
} 