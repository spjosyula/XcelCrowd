/**
 * Base request parameters for all LLM requests
 */
export interface ILLMBaseRequest {
  /**
   * The model to use
   */
  model: string;
  
  /**
   * Maximum number of tokens to generate
   */
  maxTokens?: number;
  
  /**
   * Temperature for controlling randomness (0-2)
   * Lower values make output more deterministic
   */
  temperature?: number;
  
  /**
   * Top-p sampling parameter (0-1)
   * Alternative to temperature for controlling randomness
   */
  topP?: number;
  
  /**
   * Frequency penalty to reduce repetition (0-2)
   */
  frequencyPenalty?: number;
  
  /**
   * Presence penalty to encourage topic diversity (0-2)
   */
  presencePenalty?: number;
  
  /**
   * Sequences that stop generation
   */
  stopSequences?: string[];
  
  /**
   * Unique request ID for tracking and deduplication
   */
  requestId?: string;
  
  /**
   * User ID for attribution and tracking
   */
  userId?: string;
  
  /**
   * Custom metadata for tracking
   */
  metadata?: Record<string, any>;
  
  /**
   * Whether to enable JSON mode output
   */
  jsonMode?: boolean;
  
  /**
   * Seed for deterministic outputs
   */
  seed?: number;
  
  /**
   * Whether to return token usage information
   */
  returnTokenUsage?: boolean;
  
  /**
   * Request timeout in milliseconds
   */
  timeoutMs?: number;
}

/**
 * Function parameter definition for function calling
 */
export interface ILLMFunctionParameter {
  name: string;
  description?: string;
  type: string;
  required?: boolean;
  enum?: string[];
  items?: {
    type: string;
    enum?: string[];
  };
  properties?: Record<string, ILLMFunctionParameter>;
}

/**
 * Function definition for function calling
 */
export interface ILLMFunction {
  name: string;
  description: string;
  parameters: {
    type: string;
    properties: Record<string, ILLMFunctionParameter>;
    required?: string[];
  };
}

/**
 * Function call in a message
 */
export interface ILLMFunctionCall {
  name: string;
  arguments: string;
}

/**
 * Message in a conversation
 */
export interface ILLMMessage {
  /**
   * Role of the message sender
   */
  role: 'system' | 'user' | 'assistant' | 'function';
  
  /**
   * Content of the message
   */
  content: string | null;
  
  /**
   * Name of the sender (required for function role)
   */
  name?: string;
  
  /**
   * Function call if the message contains one
   */
  functionCall?: ILLMFunctionCall;
  
  /**
   * Image URLs or base64 data for multimodal models
   */
  images?: Array<{
    url?: string;
    data?: string;
    detail?: 'low' | 'high' | 'auto';
  }>;
}

/**
 * Text generation request
 */
export interface ILLMTextRequest extends ILLMBaseRequest {
  /**
   * Conversation history
   */
  messages: ILLMMessage[];
  
  /**
   * Functions available for the model to call
   */
  functions?: ILLMFunction[];
  
  /**
   * Control function calling behavior
   */
  functionCall?: 'auto' | 'none' | { name: string };
  
  /**
   * Stream the response
   */
  stream?: boolean;
}

/**
 * Text generation response
 */
export interface ILLMTextResponse {
  /**
   * Generated text
   */
  text: string;
  
  /**
   * Function call in the response, if any
   */
  functionCall?: ILLMFunctionCall;
  
  /**
   * Token usage information
   */
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  
  /**
   * Finish reason
   */
  finishReason?: 'stop' | 'length' | 'content_filter' | 'function_call' | 'error';
  
  /**
   * Model used
   */
  model: string;
  
  /**
   * Response timestamp
   */
  timestamp: Date;
  
  /**
   * Provider-specific response data
   */
  providerResponse?: any;
}

/**
 * Streaming chunk response format
 */
export interface ILLMStreamChunk {
  /**
   * Text delta in this chunk
   */
  textDelta: string;
  
  /**
   * Accumulated text so far
   */
  text?: string;
  
  /**
   * Function call delta, if any
   */
  functionCallDelta?: {
    name?: string;
    argumentsDelta?: string;
  };
  
  /**
   * Accumulated function call data
   */
  functionCall?: ILLMFunctionCall;
  
  /**
   * Whether this is the final chunk
   */
  isComplete: boolean;
  
  /**
   * Finish reason, only on final chunk
   */
  finishReason?: 'stop' | 'length' | 'content_filter' | 'function_call' | 'error';
}

/**
 * Embedding request
 */
export interface ILLMEmbeddingRequest extends Omit<ILLMBaseRequest, 'maxTokens' | 'temperature' | 'topP' | 'frequencyPenalty' | 'presencePenalty' | 'stopSequences'> {
  /**
   * Text to generate embeddings for
   */
  input: string | string[];
  
  /**
   * Dimension of the embeddings
   */
  dimensions?: number;
  
  /**
   * Type of embeddings to return
   */
  embeddingType?: 'float' | 'int8' | 'binary';
}

/**
 * Embedding response
 */
export interface ILLMEmbeddingResponse {
  /**
   * Array of embedding vectors
   */
  embeddings: number[][];
  
  /**
   * Token usage information
   */
  usage?: {
    promptTokens: number;
    totalTokens: number;
  };
  
  /**
   * Model used
   */
  model: string;
  
  /**
   * Response timestamp
   */
  timestamp: Date;
  
  /**
   * Provider-specific response data
   */
  providerResponse?: any;
} 