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

// Import OpenAI specific tokenizer for accurate token counting
import { encode } from 'gpt-tokenizer';

/**
 * Azure OpenAI provider implementation
 * Supports Azure-hosted OpenAI models
 */
export class AzureOpenAIProvider extends AbstractLLMProvider {
  public readonly id = 'azureOpenai';
  public readonly name = 'Azure OpenAI';
  
  // List of supported models (deployment names)
  // These will be dynamically loaded based on available deployments
  public readonly models: string[] = [
    'gpt-4',
    'gpt-4-32k',
    'gpt-35-turbo',
    'text-embedding-ada-002'
  ];
  
  // Context window sizes
  protected readonly contextWindows: Record<string, IModelContextWindow> = {
    'gpt-4': {
      maxInputTokens: 8000,
      maxTotalTokens: 8192
    },
    'gpt-4-32k': {
      maxInputTokens: 32000,
      maxTotalTokens: 32768
    },
    'gpt-35-turbo': {
      maxInputTokens: 16000,
      maxTotalTokens: 16384
    },
    'text-embedding-ada-002': {
      maxInputTokens: 8191,
      maxTotalTokens: 8191
    }
  };
  
  // Model capabilities
  protected readonly capabilities: Record<string, IModelCapabilities> = {
    'gpt-4': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: false,
      maxFunctions: 64
    },
    'gpt-4-32k': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: false,
      maxFunctions: 64
    },
    'gpt-35-turbo': {
      supportsStreaming: true,
      supportsJsonMode: true,
      supportsFunctionCalling: true,
      supportsVision: false,
      maxFunctions: 64
    }
  };
  
  // Model pricing (Azure pricing is typically same as OpenAI but can be different in some contracts)
  protected readonly pricing: Record<string, IModelPricing> = {
    'gpt-4': {
      inputPerTokenCost: 0.00003, // $0.03 per 1000 tokens
      outputPerTokenCost: 0.00006, // $0.06 per 1000 tokens
      currency: 'USD'
    },
    'gpt-4-32k': {
      inputPerTokenCost: 0.00006, // $0.06 per 1000 tokens
      outputPerTokenCost: 0.00012, // $0.12 per 1000 tokens
      currency: 'USD'
    },
    'gpt-35-turbo': {
      inputPerTokenCost: 0.0000005, // $0.0005 per 1000 tokens
      outputPerTokenCost: 0.0000015, // $0.0015 per 1000 tokens
      currency: 'USD'
    },
    'text-embedding-ada-002': {
      inputPerTokenCost: 0.0000001, // $0.0001 per 1000 tokens
      outputPerTokenCost: 0, // No output tokens for embeddings
      currency: 'USD'
    }
  };
  
  // Token manager
  private tokenManager: LLMTokenManager;
  
  // Deployment model mapping
  private deploymentModelMap: Map<string, string> = new Map();
  private defaultDeployment: string;
  
  /**
   * Constructor
   */
  constructor() {
    super();
    this.tokenManager = LLMTokenManager.getInstance();
    this.defaultDeployment = config.ai.azureOpenai.defaultDeployment || '';
    
    // Initialize deployment model map
    this.initializeDeploymentMap();
  }
  
  /**
   * Initialize the deployment to model mapping
   */
  private initializeDeploymentMap(): void {
    // In a production environment, this would query the Azure OpenAI API
    // to get a list of available deployments and their models
    // For now, we'll use the default deployment if available
    if (this.defaultDeployment) {
      this.deploymentModelMap.set(this.defaultDeployment, 'gpt-4');
      logger.info(`Initialized Azure OpenAI with default deployment: ${this.defaultDeployment}`);
    } else {
      logger.warn('No default Azure OpenAI deployment specified');
    }
  }
  
  /**
   * Get deployment name for a model or vice versa
   * @param modelOrDeployment - Model or deployment name
   * @param isDeployment - Whether the input is a deployment name
   * @returns The corresponding model or deployment name
   */
  private getModelOrDeployment(modelOrDeployment: string, isDeployment: boolean = false): string {
    if (isDeployment) {
      // Convert deployment to model
      return this.deploymentModelMap.get(modelOrDeployment) || modelOrDeployment;
    } else {
      // Convert model to deployment
      for (const [deployment, model] of this.deploymentModelMap.entries()) {
        if (model === modelOrDeployment) {
          return deployment;
        }
      }
      
      // If no mapping found, use default deployment
      return this.defaultDeployment || modelOrDeployment;
    }
  }
  
  /**
   * Override normalizeModelId to handle Azure deployment names
   * @param modelId - Model or deployment name
   * @returns Normalized model ID
   */
  protected normalizeModelId(modelId: string): string {
    // Remove provider prefix if present
    if (modelId.includes(':')) {
      const [, model] = modelId.split(':');
      return model;
    }
    
    // Convert deployment name to model if necessary
    if (this.deploymentModelMap.has(modelId)) {
      return this.deploymentModelMap.get(modelId) || modelId;
    }
    
    return modelId;
  }
  
  /**
   * Generate text completion from Azure OpenAI
   * @param request - Text generation request
   * @returns Text response
   */
  public async generateText(request: ILLMTextRequest): Promise<ILLMTextResponse> {
    // Validate request
    this.validateTextRequest(request);
    
    // Normalize model ID and get deployment
    const modelId = this.normalizeModelId(request.model);
    const deploymentName = this.getModelOrDeployment(modelId) || this.defaultDeployment;
    
    if (!deploymentName) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'No deployment name specified or default deployment configured',
        true,
        'MISSING_DEPLOYMENT'
      );
    }
    
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.AZURE_OPENAI);
      if (!apiKey) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'No Azure OpenAI API key available',
          true,
          'API_KEY_UNAVAILABLE'
        );
      }
      
      // Check if endpoint is configured
      if (!config.ai.azureOpenai.endpoint) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Azure OpenAI endpoint not configured',
          true,
          'MISSING_ENDPOINT'
        );
      }
      
      // Prepare request body
      const requestBody = this.prepareAzureOpenAIRequest(request);
      
      // Make the API call
      const response = await axios({
        method: 'post',
        url: `${config.ai.azureOpenai.endpoint}/openai/deployments/${deploymentName}/chat/completions?api-version=2023-12-01-preview`,
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/json'
        },
        data: requestBody,
        timeout: request.timeoutMs || config.ai.azureOpenai.requestTimeout,
        validateStatus: null // Handle status validation ourselves
      });
      
      // Handle API errors
      if (response.status !== 200) {
        // Update API key metrics with error
        this.tokenManager.updateKeyMetrics(
          LLMProvider.AZURE_OPENAI,
          apiKey,
          false,
          undefined,
          undefined,
          `HTTP_${response.status}`
        );
        
        throw new ApiError(
          response.status,
          response.data?.error?.message || 'Unknown error from Azure OpenAI',
          true,
          response.data?.error?.type || 'AZURE_OPENAI_API_ERROR'
        );
      }
      
      // Update API key metrics with success
      this.tokenManager.updateKeyMetrics(
        LLMProvider.AZURE_OPENAI,
        apiKey,
        true
      );
      
      // Extract the response text
      const choice = response.data.choices[0];
      const text = choice.message.content || '';
      
      // Extract function call if present
      const functionCall = choice.message.function_call ? {
        name: choice.message.function_call.name,
        arguments: choice.message.function_call.arguments
      } : undefined;
      
      // Create standardized response
      const result = this.createStandardTextResponse(
        text,
        request,
        {
          promptTokens: response.data.usage.prompt_tokens,
          completionTokens: response.data.usage.completion_tokens,
          totalTokens: response.data.usage.total_tokens
        },
        choice.finish_reason,
        request.returnTokenUsage ? response.data : undefined
      );
      
      // Add function call if present
      if (functionCall) {
        result.functionCall = functionCall;
      }
      
      // Update token usage for tracking
      this.tokenManager.updateTokenUsage(
        LLMProvider.AZURE_OPENAI,
        apiKey,
        response.data.usage.prompt_tokens,
        response.data.usage.completion_tokens
      );
      
      return result;
    } catch (error) {
      throw this.handleProviderError(error, request.requestId);
    }
  }
  
  /**
   * Generate streaming text completion from Azure OpenAI
   * @param request - Text generation request
   * @returns Async generator yielding stream chunks
   */
  public async *generateTextStream(request: ILLMTextRequest): AsyncGenerator<ILLMStreamChunk> {
    // Validate request
    this.validateTextRequest(request);
    
    // Normalize model ID and get deployment
    const modelId = this.normalizeModelId(request.model);
    const deploymentName = this.getModelOrDeployment(modelId) || this.defaultDeployment;
    
    if (!deploymentName) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'No deployment name specified or default deployment configured',
        true,
        'MISSING_DEPLOYMENT'
      );
    }
    
    // Force streaming mode
    request.stream = true;
    
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.AZURE_OPENAI);
      if (!apiKey) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'No Azure OpenAI API key available',
          true,
          'API_KEY_UNAVAILABLE'
        );
      }
      
      // Check if endpoint is configured
      if (!config.ai.azureOpenai.endpoint) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Azure OpenAI endpoint not configured',
          true,
          'MISSING_ENDPOINT'
        );
      }
      
      // Prepare request body
      const requestBody = this.prepareAzureOpenAIRequest(request);
      
      // Make the API call
      const response = await axios({
        method: 'post',
        url: `${config.ai.azureOpenai.endpoint}/openai/deployments/${deploymentName}/chat/completions?api-version=2023-12-01-preview`,
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream'
        },
        data: requestBody,
        timeout: request.timeoutMs || config.ai.azureOpenai.requestTimeout,
        responseType: 'stream',
        validateStatus: null // Handle status validation ourselves
      });
      
      // Handle API errors
      if (response.status !== 200) {
        // Update API key metrics with error
        this.tokenManager.updateKeyMetrics(
          LLMProvider.AZURE_OPENAI,
          apiKey,
          false,
          undefined,
          undefined,
          `HTTP_${response.status}`
        );
        
        throw new ApiError(
          response.status,
          'Error in Azure OpenAI streaming response',
          true,
          'AZURE_OPENAI_STREAM_ERROR'
        );
      }
      
      // Update API key metrics with success
      this.tokenManager.updateKeyMetrics(
        LLMProvider.AZURE_OPENAI,
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
      
      // Set up event listeners
      const parser = new AsyncIterable(stream);
      
      for await (const chunk of parser) {
        // Skip empty chunks
        if (!chunk || chunk === '[DONE]') {
          isComplete = true;
          continue;
        }
        
        try {
          // Parse the chunk
          const data = JSON.parse(chunk);
          const delta = data.choices[0].delta;
          
          // Extract text delta
          const textDelta = delta.content || '';
          
          // Handle function calling
          let functionCallDelta;
          if (delta.function_call) {
            if (delta.function_call.name) {
              functionName = delta.function_call.name;
            }
            
            if (delta.function_call.arguments) {
              functionArgs += delta.function_call.arguments;
            }
            
            functionCallDelta = {
              name: delta.function_call.name,
              argumentsDelta: delta.function_call.arguments
            };
          }
          
          // Check if this is the final chunk
          if (data.choices[0].finish_reason) {
            finishReason = data.choices[0].finish_reason;
            isComplete = true;
          }
          
          // Update accumulated text
          accumulatedText += textDelta;
          
          // Yield the chunk
          yield {
            textDelta,
            text: accumulatedText,
            functionCallDelta,
            functionCall: functionName ? {
              name: functionName,
              arguments: functionArgs
            } : undefined,
            isComplete,
            finishReason
          };
        } catch (error) {
          logger.error('Error parsing Azure OpenAI stream chunk', {
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
      
      // Estimate token usage
      const promptTokenCount = this.estimateTokens(
        JSON.stringify(request.messages),
        modelId
      );
      const completionTokenCount = this.estimateTokens(accumulatedText, modelId);
      
      // Update token usage for tracking
      this.tokenManager.updateTokenUsage(
        LLMProvider.AZURE_OPENAI,
        apiKey,
        promptTokenCount,
        completionTokenCount
      );
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
   * Generate embeddings from Azure OpenAI
   * @param request - Embedding request
   * @returns Embedding response
   */
  public async generateEmbedding(request: ILLMEmbeddingRequest): Promise<ILLMEmbeddingResponse> {
    // Validate request
    this.validateEmbeddingRequest(request);
    
    // Normalize model ID and get deployment
    const modelId = this.normalizeModelId(request.model);
    let deploymentName = this.getModelOrDeployment(modelId) || this.defaultDeployment;
    
    // If not embedding model, try to use a default embedding deployment
    if (!modelId.includes('embedding')) {
      // In a real implementation, look for an embedding deployment
      deploymentName = 'text-embedding-ada-002'; // Default embedding model name
    }
    
    if (!deploymentName) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'No embedding deployment specified or default embedding deployment configured',
        true,
        'MISSING_EMBEDDING_DEPLOYMENT'
      );
    }
    
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.AZURE_OPENAI);
      if (!apiKey) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'No Azure OpenAI API key available',
          true,
          'API_KEY_UNAVAILABLE'
        );
      }
      
      // Check if endpoint is configured
      if (!config.ai.azureOpenai.endpoint) {
        throw new ApiError(
          HTTP_STATUS.INTERNAL_SERVER_ERROR,
          'Azure OpenAI endpoint not configured',
          true,
          'MISSING_ENDPOINT'
        );
      }
      
      // Prepare request body
      const requestBody = {
        input: request.input,
        dimensions: request.dimensions,
        user: request.userId
      };
      
      // Make the API call
      const response = await axios({
        method: 'post',
        url: `${config.ai.azureOpenai.endpoint}/openai/deployments/${deploymentName}/embeddings?api-version=2023-12-01-preview`,
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/json'
        },
        data: requestBody,
        timeout: request.timeoutMs || config.ai.azureOpenai.requestTimeout,
        validateStatus: null // Handle status validation ourselves
      });
      
      // Handle API errors
      if (response.status !== 200) {
        // Update API key metrics with error
        this.tokenManager.updateKeyMetrics(
          LLMProvider.AZURE_OPENAI,
          apiKey,
          false,
          undefined,
          undefined,
          `HTTP_${response.status}`
        );
        
        throw new ApiError(
          response.status,
          response.data?.error?.message || 'Unknown error from Azure OpenAI',
          true,
          response.data?.error?.type || 'AZURE_OPENAI_API_ERROR'
        );
      }
      
      // Update API key metrics with success
      this.tokenManager.updateKeyMetrics(
        LLMProvider.AZURE_OPENAI,
        apiKey,
        true
      );
      
      // Extract embeddings
      const embeddings = response.data.data.map((item: any) => item.embedding);
      
      // Create standardized response
      const result = this.createStandardEmbeddingResponse(
        embeddings,
        request,
        {
          promptTokens: response.data.usage.prompt_tokens,
          totalTokens: response.data.usage.total_tokens
        },
        request.returnTokenUsage ? response.data : undefined
      );
      
      // Update token usage for tracking
      this.tokenManager.updateTokenUsage(
        LLMProvider.AZURE_OPENAI,
        apiKey,
        response.data.usage.prompt_tokens,
        0 // No completion tokens for embeddings
      );
      
      return result;
    } catch (error) {
      throw this.handleProviderError(error, request.requestId);
    }
  }
  
  /**
   * Estimate token count for a text
   * @param text - Text to count tokens for
   * @param modelId - Optional model ID
   * @returns Estimated token count
   */
  public estimateTokens(text: string, modelId?: string): number {
    if (!text) return 0;
    
    try {
      // Use the gpt-tokenizer library for accurate token counting
      return encode(text).length;
    } catch (error) {
      // Fallback to a simple estimation
      logger.warn('Error estimating tokens with tokenizer, using fallback method', {
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Simple approximation: 1 token ~= 4 characters
      return Math.ceil(text.length / 4);
    }
  }
  
  /**
   * Perform health check
   * @returns Boolean indicating if provider is healthy
   */
  public async healthCheck(): Promise<boolean> {
    try {
      // Get API key
      const apiKey = this.tokenManager.getAPIKey(LLMProvider.AZURE_OPENAI);
      if (!apiKey) {
        return false;
      }
      
      // Check if endpoint is configured
      if (!config.ai.azureOpenai.endpoint) {
        return false;
      }
      
      // Try to get a list of deployments
      const response = await axios({
        method: 'get',
        url: `${config.ai.azureOpenai.endpoint}/openai/deployments?api-version=2023-12-01-preview`,
        headers: {
          'api-key': apiKey
        },
        timeout: 5000, // Short timeout for health check
        validateStatus: null
      });
      
      // Update the deployment model map if successful
      if (response.status === 200 && response.data?.data) {
        this.deploymentModelMap.clear();
        
        for (const deployment of response.data.data) {
          this.deploymentModelMap.set(deployment.id, deployment.model);
          logger.debug(`Found Azure OpenAI deployment: ${deployment.id} (${deployment.model})`);
        }
      }
      
      return response.status === 200;
    } catch (error) {
      logger.error('Azure OpenAI health check failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      return false;
    }
  }
  
  /**
   * Prepare Azure OpenAI request payload
   * @param request - Text generation request
   * @returns Azure OpenAI API request body
   */
  private prepareAzureOpenAIRequest(request: ILLMTextRequest): any {
    // Convert messages to OpenAI format
    const messages = request.messages.map(message => {
      const azureOpenAIMessage: any = {
        role: message.role,
        content: message.content
      };
      
      // Add name if present
      if (message.name) {
        azureOpenAIMessage.name = message.name;
      }
      
      // Add function call if present
      if (message.functionCall) {
        azureOpenAIMessage.function_call = {
          name: message.functionCall.name,
          arguments: message.functionCall.arguments
        };
      }
      
      // Handle multimodal messages with images
      if (message.images && message.images.length > 0) {
        azureOpenAIMessage.content = [];
        
        // Add text content if exists
        if (message.content) {
          azureOpenAIMessage.content.push({
            type: 'text',
            text: message.content
          });
        }
        
        // Add images
        for (const image of message.images) {
          const imageContent: any = {
            type: 'image_url'
          };
          
          if (image.url) {
            imageContent.image_url = {
              url: image.url
            };
          } else if (image.data) {
            imageContent.image_url = {
              url: `data:image/jpeg;base64,${image.data}`
            };
          }
          
          // Add detail level if specified
          if (image.detail) {
            imageContent.image_url.detail = image.detail;
          }
          
          azureOpenAIMessage.content.push(imageContent);
        }
      }
      
      return azureOpenAIMessage;
    });
    
    // Prepare the request body
    const requestBody: any = {
      messages,
      stream: !!request.stream
    };
    
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
    
    if (request.frequencyPenalty !== undefined) {
      requestBody.frequency_penalty = request.frequencyPenalty;
    }
    
    if (request.presencePenalty !== undefined) {
      requestBody.presence_penalty = request.presencePenalty;
    }
    
    if (request.stopSequences && request.stopSequences.length > 0) {
      requestBody.stop = request.stopSequences;
    }
    
    if (request.seed !== undefined) {
      requestBody.seed = request.seed;
    }
    
    if (request.jsonMode) {
      requestBody.response_format = { type: 'json_object' };
    }
    
    if (request.functions && request.functions.length > 0) {
      requestBody.tools = request.functions.map(fn => ({
        type: 'function',
        function: {
          name: fn.name,
          description: fn.description,
          parameters: fn.parameters
        }
      }));
      
      if (request.functionCall) {
        if (request.functionCall === 'auto' || request.functionCall === 'none') {
          requestBody.tool_choice = request.functionCall;
        } else {
          requestBody.tool_choice = {
            type: 'function',
            function: {
              name: request.functionCall.name
            }
          };
        }
      }
    }
    
    // Add user if specified
    if (request.userId) {
      requestBody.user = request.userId;
    }
    
    return requestBody;
  }
}

/**
 * Helper class to handle Azure OpenAI streaming
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