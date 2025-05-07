import { logger } from '../../../utils/logger';
import { ApiError } from '../../../utils/api.error';
import { HTTP_STATUS } from '../../../models/interfaces';
import { v4 as uuidv4 } from 'uuid';
import { 
  ILLMProvider, 
  IModelCapabilities,
  IModelContextWindow,
  IModelPricing
} from '../interfaces/ILLMProvider';
import { 
  ILLMTextRequest, 
  ILLMTextResponse,
  ILLMEmbeddingRequest,
  ILLMEmbeddingResponse,
  ILLMStreamChunk
} from '../interfaces/ILLMRequest';

/**
 * Abstract base class for LLM providers
 * Implements common functionality and defines interface for concrete providers
 */
export abstract class AbstractLLMProvider implements ILLMProvider {
  /**
   * Provider unique identifier
   */
  public abstract readonly id: string;
  
  /**
   * Provider display name
   */
  public abstract readonly name: string;
  
  /**
   * List of models supported by this provider
   */
  public abstract readonly models: string[];
  
  /**
   * Model context window sizes (tokens)
   */
  protected abstract readonly contextWindows: Record<string, IModelContextWindow>;
  
  /**
   * Model capabilities
   */
  protected abstract readonly capabilities: Record<string, IModelCapabilities>;
  
  /**
   * Model pricing
   */
  protected abstract readonly pricing: Record<string, IModelPricing>;
  
  /**
   * Check if a model is supported by this provider
   * @param modelId - The model to check
   * @returns Boolean indicating if model is supported
   */
  public supportsModel(modelId: string): boolean {
    // Strip provider prefix if present
    const normalizedModelId = this.normalizeModelId(modelId);
    return this.models.includes(normalizedModelId);
  }
  
  /**
   * Get model context window size
   * @param modelId - The model
   * @returns Context window information
   */
  public getModelContext(modelId: string): IModelContextWindow {
    const normalizedModelId = this.normalizeModelId(modelId);
    
    // Try to get the specific model
    if (this.contextWindows[normalizedModelId]) {
      return this.contextWindows[normalizedModelId];
    }
    
    // Try to get a default for the model family
    const modelFamily = this.getModelFamily(normalizedModelId);
    if (this.contextWindows[modelFamily]) {
      return this.contextWindows[modelFamily];
    }
    
    // Return a conservative default
    logger.warn(`No context window information for model ${modelId}, using default`);
    return {
      maxInputTokens: 4000,
      maxTotalTokens: 8000
    };
  }
  
  /**
   * Get model capabilities
   * @param modelId - The model
   * @returns Capabilities information
   */
  public getModelCapabilities(modelId: string): IModelCapabilities {
    const normalizedModelId = this.normalizeModelId(modelId);
    
    // Try to get the specific model
    if (this.capabilities[normalizedModelId]) {
      return this.capabilities[normalizedModelId];
    }
    
    // Try to get a default for the model family
    const modelFamily = this.getModelFamily(normalizedModelId);
    if (this.capabilities[modelFamily]) {
      return this.capabilities[modelFamily];
    }
    
    // Return a conservative default
    logger.warn(`No capabilities information for model ${modelId}, using default`);
    return {
      supportsStreaming: false,
      supportsJsonMode: false,
      supportsFunctionCalling: false,
      supportsVision: false
    };
  }
  
  /**
   * Get model pricing information
   * @param modelId - The model
   * @returns Pricing information
   */
  public getModelPricing(modelId: string): IModelPricing {
    const normalizedModelId = this.normalizeModelId(modelId);
    
    // Try to get the specific model
    if (this.pricing[normalizedModelId]) {
      return this.pricing[normalizedModelId];
    }
    
    // Try to get a default for the model family
    const modelFamily = this.getModelFamily(normalizedModelId);
    if (this.pricing[modelFamily]) {
      return this.pricing[modelFamily];
    }
    
    // Return a conservative default
    logger.warn(`No pricing information for model ${modelId}, using default`);
    return {
      inputPerTokenCost: 0.00001, // $0.01 per 1000 tokens
      outputPerTokenCost: 0.00002, // $0.02 per 1000 tokens
      currency: 'USD'
    };
  }
  
  /**
   * Check if streaming is supported for a model
   * @param modelId - The model
   * @returns Boolean indicating if streaming is supported
   */
  public supportsStreaming(modelId: string): boolean {
    return this.getModelCapabilities(modelId).supportsStreaming;
  }
  
  /**
   * Generate text completion
   * @param request - The text generation request
   * @returns A promise resolving to the text response
   */
  public abstract generateText(request: ILLMTextRequest): Promise<ILLMTextResponse>;
  
  /**
   * Generate streaming text completion
   * @param request - The text generation request
   * @returns An async generator yielding stream chunks
   */
  public abstract generateTextStream?(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk>;
  
  /**
   * Generate embeddings
   * @param request - The embedding request
   * @returns A promise resolving to the embedding response
   */
  public abstract generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse>;
  
  /**
   * Estimate token count for a text
   * @param text - The text to estimate
   * @param modelId - Optional model ID for model-specific counting
   * @returns Estimated token count
   */
  public abstract estimateTokens(text: string, modelId?: string): number;
  
  /**
   * Perform a health check on this provider
   * @returns A promise resolving to a boolean indicating if provider is healthy
   */
  public abstract healthCheck(): Promise<boolean>;
  
  /**
   * Normalize a model ID by removing provider prefix if present
   * @param modelId - The model ID
   * @returns Normalized model ID
   */
  protected normalizeModelId(modelId: string): string {
    // Remove provider prefix if present (e.g., "openai:gpt-4" -> "gpt-4")
    if (modelId.includes(':')) {
      const [, model] = modelId.split(':');
      return model;
    }
    return modelId;
  }
  
  /**
   * Get model family from a specific model version
   * E.g., "gpt-4-turbo" -> "gpt-4"
   * @param modelId - The model ID
   * @returns Model family ID
   */
  protected getModelFamily(modelId: string): string {
    // Extract main model family name
    if (modelId.startsWith('gpt-4')) {
      return 'gpt-4';
    } else if (modelId.startsWith('gpt-3.5')) {
      return 'gpt-3.5';
    } else if (modelId.startsWith('claude-3')) {
      // Split on hyphen and get first two parts
      const parts = modelId.split('-');
      if (parts.length >= 3) {
        return `${parts[0]}-${parts[1]}-${parts[2]}`;
      }
    }
    
    // If no specific pattern matches, return first two segments
    const parts = modelId.split('-');
    if (parts.length >= 2) {
      return `${parts[0]}-${parts[1]}`;
    }
    
    return modelId;
  }
  
  /**
   * Create a standard LLM response object
   * @param text - Response text
   * @param request - Original request
   * @param usage - Token usage info
   * @param finishReason - Reason for completion
   * @param provider - Raw provider response
   * @returns Standardized response object
   */
  protected createStandardTextResponse(
    text: string,
    request: ILLMTextRequest,
    usage?: { promptTokens: number; completionTokens: number; totalTokens: number },
    finishReason?: 'stop' | 'length' | 'content_filter' | 'function_call' | 'error',
    providerResponse?: any
  ): ILLMTextResponse {
    return {
      text,
      model: request.model,
      timestamp: new Date(),
      usage,
      finishReason,
      providerResponse: request.returnTokenUsage ? providerResponse : undefined
    };
  }
  
  /**
   * Create a standard LLM embedding response object
   * @param embeddings - Embedding vectors
   * @param request - Original request
   * @param usage - Token usage info
   * @param provider - Raw provider response
   * @returns Standardized response object
   */
  protected createStandardEmbeddingResponse(
    embeddings: number[][],
    request: ILLMEmbeddingRequest,
    usage?: { promptTokens: number; totalTokens: number },
    providerResponse?: any
  ): ILLMEmbeddingResponse {
    return {
      embeddings,
      model: request.model,
      timestamp: new Date(),
      usage,
      providerResponse: request.returnTokenUsage ? providerResponse : undefined
    };
  }
  
  /**
   * Validate a request has all required fields
   * @param request - The request to validate
   * @throws ApiError if validation fails
   */
  protected validateTextRequest(request: ILLMTextRequest): void {
    if (!request.model) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Model is required',
        true,
        'MISSING_MODEL'
      );
    }
    
    if (!request.messages || request.messages.length === 0) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Messages are required',
        true,
        'MISSING_MESSAGES'
      );
    }
    
    // Ensure requestId is set
    if (!request.requestId) {
      request.requestId = uuidv4();
    }
    
    // Validate against model capabilities
    if (request.functions && request.functions.length > 0) {
      const capabilities = this.getModelCapabilities(request.model);
      
      if (!capabilities.supportsFunctionCalling) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Model ${request.model} does not support function calling`,
          true,
          'UNSUPPORTED_FEATURE'
        );
      }
      
      if (capabilities.maxFunctions && request.functions.length > capabilities.maxFunctions) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Model ${request.model} supports at most ${capabilities.maxFunctions} functions, but ${request.functions.length} were provided`,
          true,
          'TOO_MANY_FUNCTIONS'
        );
      }
    }
    
    if (request.jsonMode) {
      const capabilities = this.getModelCapabilities(request.model);
      
      if (!capabilities.supportsJsonMode) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Model ${request.model} does not support JSON mode`,
          true,
          'UNSUPPORTED_FEATURE'
        );
      }
    }
  }
  
  /**
   * Validate an embedding request has all required fields
   * @param request - The request to validate
   * @throws ApiError if validation fails
   */
  protected validateEmbeddingRequest(request: ILLMEmbeddingRequest): void {
    if (!request.model) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Model is required',
        true,
        'MISSING_MODEL'
      );
    }
    
    if (!request.input) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Input is required',
        true,
        'MISSING_INPUT'
      );
    }
    
    // Ensure requestId is set
    if (!request.requestId) {
      request.requestId = uuidv4();
    }
  }
  
  /**
   * Process error from provider API
   * @param error - The error object
   * @param requestId - Optional request ID for logging
   * @returns Standardized error
   */
  protected handleProviderError(error: any, requestId?: string): Error {
    // Build base error properties
    let statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR;
    let message = 'Unknown error from LLM provider';
    let errorCode = 'PROVIDER_ERROR';
    
    // Extract useful information from provider errors
    if (error.response) {
      statusCode = error.response.status;
      
      // Extract error message from response body
      if (error.response.data) {
        if (error.response.data.error) {
          message = error.response.data.error.message || error.response.data.error;
          if (error.response.data.error.code) {
            errorCode = error.response.data.error.code;
          } else if (error.response.data.error.type) {
            errorCode = error.response.data.error.type;
          }
        } else if (error.response.data.message) {
          message = error.response.data.message;
        }
      }
      
      // Map common status codes to appropriate error types
      if (statusCode === 401 || statusCode === 403) {
        errorCode = 'AUTHENTICATION_ERROR';
      } else if (statusCode === 429) {
        errorCode = 'RATE_LIMIT_EXCEEDED';
      } else if (statusCode >= 500) {
        errorCode = 'PROVIDER_SERVER_ERROR';
      }
    } else if (error.code === 'ECONNABORTED') {
      statusCode = HTTP_STATUS.GATEWAY_TIMEOUT;
      message = 'Request to LLM provider timed out';
      errorCode = 'TIMEOUT_ERROR';
    } else if (error.code === 'ECONNREFUSED') {
      message = 'Could not connect to LLM provider';
      errorCode = 'CONNECTION_ERROR';
    } else if (error instanceof Error) {
      message = error.message;
    }
    
    // Log the error with details
    logger.error(`Error from LLM provider ${this.id}`, {
      provider: this.id,
      statusCode,
      errorCode,
      message,
      requestId,
      originalError: error instanceof Error ? error.message : String(error)
    });
    
    // Return as API error
    return new ApiError(
      statusCode,
      message,
      true,
      errorCode
    );
  }
} 