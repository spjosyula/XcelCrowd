import axios from 'axios';
import { setTimeout } from 'timers/promises';
import { AbstractLLMProvider } from './AbstractLLMProvider';
import { 
  ILLMTextRequest, 
  ILLMTextResponse, 
  ILLMEmbeddingRequest, 
  ILLMEmbeddingResponse,
  ILLMStreamChunk,
  ILLMMessage,
  ILLMFunction
} from '../interfaces/ILLMRequest';
import { 
  IModelCapabilities, 
  IModelContextWindow, 
  IModelPricing 
} from '../interfaces/ILLMProvider';
import { LLMProvider, LLMTokenManager } from '../../../config/llm.token.manager';
import { config } from '../../../config/config.env.validation';
import { logger } from '../../../utils/logger';
import { ApiError } from '../../../utils/api.error';
import { HTTP_STATUS } from '../../../models/interfaces';

/**
 * Anthropic provider implementation
 * Supports Claude 3 models (Opus, Sonnet, Haiku)
 */
export class AnthropicProvider extends AbstractLLMProvider {
  public readonly id = 'anthropic';
  public readonly name = 'Anthropic';
  
  // List of supported models
  public readonly models = [
    'claude-3-opus-20240229',
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307',
    'claude-3-5-sonnet-20240620',
    'claude-3-7-sonnet-20240307'
  ];
  
  // Context window sizes
  protected readonly contextWindows: Record<string, IModelContextWindow> = {
    'claude-3-opus-20240229': {
      maxInputTokens: 200000,
      maxTotalTokens: 200000
    },
    'claude-3-sonnet-20240229': {
      maxInputTokens: 200000,
      maxTotalTokens: 200000
    },
    'claude-3-haiku-20240307': {
      maxInputTokens: 200000,
      maxTotalTokens: 200000
    },
    'claude-3-5-sonnet-20240620': {
      maxInputTokens: 200000,
      maxTotalTokens: 200000
    },
    'claude-3-7-sonnet-20240307': {
      maxInputTokens: 200000,
      maxTotalTokens: 200000
    }
  };
  
  // Model capabilities
  protected readonly capabilities: Record<string, IModelCapabilities> = {
    'claude-3-opus-20240229': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: true,
      maxFunctions: 128
    },
    'claude-3-sonnet-20240229': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: true,
      maxFunctions: 128
    },
    'claude-3-haiku-20240307': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: true,
      maxFunctions: 128
    },
    'claude-3-5-sonnet-20240620': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: true,
      maxFunctions: 128
    },
    'claude-3-7-sonnet-20240307': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: true,
      maxFunctions: 128
    }
  };
  
  // Model pricing
  protected readonly pricing: Record<string, IModelPricing> = {
    'claude-3-opus-20240229': {
      inputPerTokenCost: 0.00008, // $0.08 per 1000 tokens
      outputPerTokenCost: 0.00024, // $0.24 per 1000 tokens
      currency: 'USD'
    },
    'claude-3-sonnet-20240229': {
      inputPerTokenCost: 0.000003, // $0.003 per 1000 tokens
      outputPerTokenCost: 0.000015, // $0.015 per 1000 tokens
      currency: 'USD'
    },
    'claude-3-haiku-20240307': {
      inputPerTokenCost: 0.00000025, // $0.00025 per 1000 tokens
      outputPerTokenCost: 0.00000125, // $0.00125 per 1000 tokens
      currency: 'USD'
    },
    'claude-3-5-sonnet-20240620': {
      inputPerTokenCost: 0.000003, // $0.003 per 1000 tokens
      outputPerTokenCost: 0.000015, // $0.015 per 1000 tokens
      currency: 'USD'
    },
    'claude-3-7-sonnet-20240307': {
      inputPerTokenCost: 0.000005, // $0.005 per 1000 tokens
      outputPerTokenCost: 0.000025, // $0.025 per 1000 tokens
      currency: 'USD'
    }
  };
  
  // Token manager
  private tokenManager: LLMTokenManager;
  
  /**
   * Constructor
   */
  constructor() {
    super();
    this.tokenManager = LLMTokenManager.getInstance();
  }
  
  /**
   * Generate text completion from Anthropic
   * @param request - Text generation request
   * @returns Text response
   */
  public async generateText(request: ILLMTextRequest): Promise<ILLMTextResponse> {
    // Validate request
    this.validateTextRequest(request);
    
    // Normalize model ID
    const modelId = this.normalizeModelId(request.model);
    
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.ANTHROPIC);
      if (!apiKey) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'No Anthropic API key available',
          true,
          'API_KEY_UNAVAILABLE'
        );
      }
      
      // Prepare request body
      const requestBody = this.prepareAnthropicRequest(request);
      
      // Determine API base URL
      const apiBaseUrl = config.ai.anthropic.apiBaseUrl || 'https://api.anthropic.com';
      
      // Make the API call
      const response = await axios({
        method: 'post',
        url: `${apiBaseUrl}/v1/messages`,
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json'
        },
        data: requestBody,
        timeout: request.timeoutMs || config.ai.anthropic.requestTimeout,
        validateStatus: null // Handle status validation ourselves
      });
      
      // Handle API errors
      if (response.status !== 200) {
        // Update API key metrics with error
        this.tokenManager.updateKeyMetrics(
          LLMProvider.ANTHROPIC,
          apiKey,
          false,
          undefined,
          undefined,
          `HTTP_${response.status}`
        );
        
        throw new ApiError(
          response.status,
          response.data?.error?.message || 'Unknown error from Anthropic',
          true,
          response.data?.error?.type || 'ANTHROPIC_API_ERROR'
        );
      }
      
      // Update API key metrics with success
      this.tokenManager.updateKeyMetrics(
        LLMProvider.ANTHROPIC,
        apiKey,
        true
      );
      
      // Extract the response text
      const text = response.data.content && response.data.content.length > 0 
        ? response.data.content.map((content: any) => {
            if (content.type === 'text') return content.text;
            return '';
          }).join('')
        : '';
      
      // Extract function call if present
      let functionCall = undefined;
      const toolUse = response.data.content.find((content: any) => content.type === 'tool_use');
      if (toolUse) {
        functionCall = {
          name: toolUse.name,
          arguments: JSON.stringify(toolUse.input)
        };
      }
      
      // Create standardized response
      const result = this.createStandardTextResponse(
        text,
        request,
        {
          promptTokens: response.data.usage?.input_tokens || 0,
          completionTokens: response.data.usage?.output_tokens || 0,
          totalTokens: (response.data.usage?.input_tokens || 0) + (response.data.usage?.output_tokens || 0)
        },
        response.data.stop_reason === 'stop_sequence' ? 'stop' : 
        response.data.stop_reason === 'max_tokens' ? 'length' : 
        response.data.stop_reason,
        request.returnTokenUsage ? response.data : undefined
      );
      
      // Add function call if present
      if (functionCall) {
        result.functionCall = functionCall;
      }
      
      // Update token usage for tracking
      this.tokenManager.updateTokenUsage(
        LLMProvider.ANTHROPIC,
        apiKey,
        response.data.usage?.input_tokens || 0,
        response.data.usage?.output_tokens || 0
      );
      
      return result;
    } catch (error) {
      throw this.handleProviderError(error, request.requestId);
    }
  }
  
  /**
   * Generate streaming text completion from Anthropic
   * @param request - Text generation request
   * @returns Async generator yielding stream chunks
   */
  public async *generateTextStream(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk> {
    // Validate request
    this.validateTextRequest(request);
    
    // Normalize model ID
    const modelId = this.normalizeModelId(request.model);
    
    // Force streaming mode
    request.stream = true;
    
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.ANTHROPIC);
      if (!apiKey) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'No Anthropic API key available',
          true,
          'API_KEY_UNAVAILABLE'
        );
      }
      
      // Prepare request body
      const requestBody = this.prepareAnthropicRequest(request);
      
      // Determine API base URL
      const apiBaseUrl = config.ai.anthropic.apiBaseUrl || 'https://api.anthropic.com';
      
      // Make the API call
      const response = await axios({
        method: 'post',
        url: `${apiBaseUrl}/v1/messages`,
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream'
        },
        data: requestBody,
        timeout: request.timeoutMs || config.ai.anthropic.requestTimeout,
        responseType: 'stream',
        validateStatus: null // Handle status validation ourselves
      });
      
      // Handle API errors
      if (response.status !== 200) {
        // Update API key metrics with error
        this.tokenManager.updateKeyMetrics(
          LLMProvider.ANTHROPIC,
          apiKey,
          false,
          undefined,
          undefined,
          `HTTP_${response.status}`
        );
        
        throw new ApiError(
          response.status,
          'Error in Anthropic streaming response',
          true,
          'ANTHROPIC_STREAM_ERROR'
        );
      }
      
      // Update API key metrics with success
      this.tokenManager.updateKeyMetrics(
        LLMProvider.ANTHROPIC,
        apiKey,
        true
      );
      
      // Process the streaming response
      const stream = response.data;
      let accumulatedText = '';
      let functionName = '';
      let functionArgs = '';
      let isComplete = false;
      let finishReason: 'stop' | 'length' | 'content_filter' | 'function_call' | 'error' | undefined;
      let inputTokens = 0;
      let outputTokens = 0;
      
      // Set up event listeners
      const parser = new AsyncIterable(stream);
      
      for await (const chunk of parser) {
        // Skip empty chunks
        if (!chunk) continue;
        
        try {
          // Parse the chunk
          const data = JSON.parse(chunk);
          
          // If this is a content block
          if (data.type === 'content_block_delta') {
            const delta = data.delta;
            
            // Extract text delta
            let textDelta = '';
            if (delta.type === 'text_delta') {
              textDelta = delta.text || '';
              accumulatedText += textDelta;
            }
            
            // Handle function calling (tool_use)
            let functionCallDelta;
            if (delta.type === 'tool_use_delta') {
              if (delta.name) {
                functionName = delta.name;
              }
              
              if (delta.input) {
                const inputUpdate = JSON.stringify(delta.input);
                functionArgs = functionArgs ? functionArgs.slice(0, -1) + ',' + inputUpdate.slice(1) : inputUpdate;
              }
              
              functionCallDelta = {
                name: delta.name,
                argumentsDelta: delta.input ? JSON.stringify(delta.input) : undefined
              };
            }
            
            // Yield the chunk
            yield {
              textDelta,
              text: accumulatedText,
              functionCallDelta,
              functionCall: functionName ? {
                name: functionName,
                arguments: functionArgs
              } : undefined,
              isComplete: false
            };
          }
          
          // If this is a message stop event
          if (data.type === 'message_stop') {
            isComplete = true;
            finishReason = data.stop_reason === 'stop_sequence' ? 'stop' : 
                          data.stop_reason === 'max_tokens' ? 'length' : 
                          data.stop_reason;
                          
            // Capture token usage
            if (data.usage) {
              inputTokens = data.usage.input_tokens;
              outputTokens = data.usage.output_tokens;
            }
            
            // Yield the final chunk
            yield {
              textDelta: '',
              text: accumulatedText,
              functionCall: functionName ? {
                name: functionName,
                arguments: functionArgs
              } : undefined,
              isComplete: true,
              finishReason
            };
          }
        } catch (error) {
          logger.error('Error parsing Anthropic stream chunk', {
            error: error instanceof Error ? error.message : String(error),
            chunk
          });
        }
      }
      
      // Always send a final chunk if we haven't already
      if (!isComplete) {
        yield {
          textDelta: '',
          text: accumulatedText,
          functionCall: functionName ? {
            name: functionName,
            arguments: functionArgs
          } : undefined,
          isComplete: true,
          finishReason: 'stop'
        };
      }
      
      // If we have token usage, update it
      if (inputTokens > 0 || outputTokens > 0) {
        this.tokenManager.updateTokenUsage(
          LLMProvider.ANTHROPIC,
          apiKey,
          inputTokens,
          outputTokens
        );
      } else {
        // If no token info, estimate
        const promptTokenCount = this.estimateTokens(
          JSON.stringify(request.messages),
          modelId
        );
        const completionTokenCount = this.estimateTokens(accumulatedText, modelId);
        
        // Update token usage for tracking
        this.tokenManager.updateTokenUsage(
          LLMProvider.ANTHROPIC,
          apiKey,
          promptTokenCount,
          completionTokenCount
        );
      }
    } catch (error) {
      const errorObj = this.handleProviderError(error, request.requestId);
      
      // Yield the error as a chunk
      yield {
        textDelta: '',
        text: errorObj.message,
        isComplete: true,
        finishReason: 'error'
      };
    }
  }
  
  /**
   * Generate embeddings from Anthropic
   * Note: Claude currently doesn't support embeddings directly, so we'll throw an error
   * @param request - Embedding request
   * @returns Embedding response
   */
  public async generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse> {
    throw new ApiError(
      HTTP_STATUS.NOT_FOUND,
      'Anthropic Claude does not support embeddings directly',
      true,
      'EMBEDDINGS_NOT_SUPPORTED'
    );
  }
  
  /**
   * Estimate token count for a text
   * @param text - Text to count tokens for
   * @param modelId - Optional model ID
   * @returns Estimated token count
   */
  public estimateTokens(text: string, modelId?: string): number {
    if (!text) return 0;
    
    // Claude has a similar tokenizer to GPT-3
    // Average token is ~4 characters in English
    return Math.ceil(text.length / 4);
  }
  
  /**
   * Perform health check
   * @returns Boolean indicating if provider is healthy
   */
  public async healthCheck(): Promise<boolean> {
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.ANTHROPIC);
      if (!apiKey) {
        return false;
      }
      
      // Determine API base URL
      const apiBaseUrl = config.ai.anthropic.apiBaseUrl || 'https://api.anthropic.com';
      
      // Make a simple models request to test connectivity
      const response = await axios({
        method: 'get',
        url: `${apiBaseUrl}/v1/models`,
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        timeout: 5000, // Short timeout for health check
        validateStatus: null
      });
      
      return response.status === 200;
    } catch (error) {
      logger.error('Anthropic health check failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      return false;
    }
  }
  
  /**
   * Prepare Anthropic completion request payload
   * @param request - Text generation request
   * @returns Anthropic API request body
   */
  private prepareAnthropicRequest(request: ILLMTextRequest): any {
    // Convert from our unified format to Anthropic's expected format
    const messages: any[] = [];
    
    // Convert our messages to Anthropic format
    for (const message of request.messages) {
      if (message.role === 'system') {
        // System messages are handled separately in Anthropic API
        continue;
      }
      
      // Build the message
      const anthropicMessage: any = {
        role: message.role === 'assistant' ? 'assistant' : 'user',
        content: []
      };
      
      // Handle content
      if (message.content) {
        anthropicMessage.content.push({
          type: 'text',
          text: message.content
        });
      }
      
      // Handle images
      if (message.images && message.images.length > 0) {
        for (const image of message.images) {
          if (image.url) {
            anthropicMessage.content.push({
              type: 'image',
              source: {
                type: 'url',
                url: image.url
              }
            });
          } else if (image.data) {
            anthropicMessage.content.push({
              type: 'image',
              source: {
                type: 'base64',
                media_type: 'image/jpeg',
                data: image.data
              }
            });
          }
        }
      }
      
      messages.push(anthropicMessage);
    }
    
    // Extract system message
    const systemMessage = request.messages.find(m => m.role === 'system')?.content || '';
    
    // Prepare the request body
    const requestBody: any = {
      model: this.normalizeModelId(request.model),
      messages: messages,
      stream: !!request.stream
    };
    
    // Add system message if present
    if (systemMessage) {
      requestBody.system = systemMessage;
    }
    
    // Add optional parameters if specified
    if (request.temperature !== undefined) {
      requestBody.temperature = request.temperature;
    }
    
    if (request.maxTokens !== undefined) {
      requestBody.max_tokens = request.maxTokens;
    }
    
    if (request.topP !== undefined) {
      requestBody.top_p = request.topP;
    }
    
    if (request.stopSequences && request.stopSequences.length > 0) {
      requestBody.stop_sequences = request.stopSequences;
    }
    
    // Handle function calling (tools)
    if (request.functions && request.functions.length > 0) {
      requestBody.tools = request.functions.map(fn => ({
        name: fn.name,
        description: fn.description,
        input_schema: fn.parameters
      }));
    }
    
    // Add metadata if specified
    if (request.metadata) {
      requestBody.metadata = request.metadata;
    }
    
    return requestBody;
  }
}

/**
 * Helper class to handle Anthropic streaming
 */
class AsyncIterable {
  private buffer = '';
  private stream: NodeJS.ReadableStream;
  
  constructor(stream: NodeJS.ReadableStream) {
    this.stream = stream;
  }
  
  [Symbol.asyncIterator]() {
    return {
      next: async () => {
        // Return cached chunk if available
        if (this.buffer.includes('\n\n')) {
          const parts = this.buffer.split('\n\n');
          this.buffer = parts.pop() || '';
          
          // Process only data: prefixed lines
          const chunk = parts
            .map(part => part.replace(/^data: /, '').trim())
            .filter(part => part !== '')
            .join('');
          
          return { done: false, value: chunk };
        }
        
        // Read more data
        return new Promise<IteratorResult<string>>((resolve, reject) => {
          const onData = (data: Buffer) => {
            this.buffer += data.toString();
            
            if (this.buffer.includes('\n\n')) {
              cleanup();
              
              const parts = this.buffer.split('\n\n');
              this.buffer = parts.pop() || '';
              
              // Process only data: prefixed lines
              const chunk = parts
                .map(part => part.replace(/^data: /, '').trim())
                .filter(part => part !== '')
                .join('');
              
              resolve({ done: false, value: chunk });
            }
          };
          
          const onEnd = () => {
            cleanup();
            
            // Process any remaining buffer
            if (this.buffer.trim()) {
              const chunk = this.buffer.replace(/^data: /, '').trim();
              this.buffer = '';
              resolve({ done: false, value: chunk });
            } else {
              resolve({ done: true, value: '' });
            }
          };
          
          const onError = (err: Error) => {
            cleanup();
            reject(err);
          };
          
          const cleanup = () => {
            this.stream.removeListener('data', onData);
            this.stream.removeListener('end', onEnd);
            this.stream.removeListener('error', onError);
          };
          
          this.stream.on('data', onData);
          this.stream.on('end', onEnd);
          this.stream.on('error', onError);
        });
      }
    };
  }
} 