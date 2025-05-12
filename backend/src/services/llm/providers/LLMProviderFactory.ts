import { singleton } from 'tsyringe';
import { logger } from '../../../utils/logger';
import { config } from '../../../config/config.env.validation';
import { LLMProvider } from '../../../config/llm.token.manager';
import { ILLMProvider } from '../interfaces/ILLMProvider';
import { OpenAIProvider } from './OpenAIProvider';
import { AnthropicProvider } from './AnthropicProvider';
import { AzureOpenAIProvider } from './AzureOpenAIProvider';
import { ApiError } from '../../../utils/api.error';
import { HTTP_STATUS } from '../../../constants';

/**
 * Factory for creating and managing LLM provider instances
 * Abstracts provider selection and initialization
 */
@singleton()
export class LLMProviderFactory {
  private static instance: LLMProviderFactory;
  private readonly providers: Map<LLMProvider, ILLMProvider> = new Map();
  
  /**
   * Constructor
   * Initializes provider instances
   */
  constructor() {
    // Initialize providers
    this.initializeProviders();
    
    logger.info('LLM provider factory initialized', {
      availableProviders: Array.from(this.providers.keys()),
      defaultProvider: config.ai.global.provider
    });
  }
  
  /**
   * Get singleton instance
   */
  public static getInstance(): LLMProviderFactory {
    if (!LLMProviderFactory.instance) {
      LLMProviderFactory.instance = new LLMProviderFactory();
    }
    return LLMProviderFactory.instance;
  }
  
  /**
   * Initialize all provider instances
   */
  private initializeProviders(): void {
    try {
      // Initialize OpenAI provider if API keys are configured
      if (config.ai.openai.apiKeys.length > 0) {
        this.providers.set(LLMProvider.OPENAI, new OpenAIProvider());
      }
      
      // Initialize Anthropic provider if API keys are configured
      if (config.ai.anthropic.apiKeys.length > 0) {
        this.providers.set(LLMProvider.ANTHROPIC, new AnthropicProvider());
      }
      
      // Initialize Azure OpenAI provider if API keys are configured
      if (config.ai.azureOpenai.apiKeys.length > 0 && config.ai.azureOpenai.endpoint) {
        this.providers.set(LLMProvider.AZURE_OPENAI, new AzureOpenAIProvider());
      }
      
      // Log warning if no providers are configured
      if (this.providers.size === 0) {
        logger.warn('No LLM providers configured. Please check your environment variables.');
      }
    } catch (error) {
      logger.error('Error initializing LLM providers', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error; // Re-throw as this is a critical error
    }
  }
  
  /**
   * Get a provider by ID
   * @param provider - Provider enum
   * @returns Provider instance
   * @throws ApiError if provider not found or initialized
   */
  public getProvider(provider: LLMProvider): ILLMProvider {
    const providerInstance = this.providers.get(provider);
    
    if (!providerInstance) {
      // If requested provider is not available, try to use default provider
      if (provider !== config.ai.global.provider as LLMProvider) {
        logger.warn(`Provider ${provider} not found, falling back to default provider`);
        return this.getProvider(config.ai.global.provider as LLMProvider);
      }
      
      // If default provider is also not available, throw error
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Provider ${provider} not configured or initialized`,
        true,
        'PROVIDER_NOT_AVAILABLE'
      );
    }
    
    return providerInstance;
  }
  
  /**
   * Get the default LLM provider
   * @returns Default provider instance
   * @throws ApiError if default provider not found or initialized
   */
  public getDefaultProvider(): ILLMProvider {
    const defaultProvider = config.ai.global.provider as LLMProvider;
    return this.getProvider(defaultProvider);
  }
  
  /**
   * Get all available providers
   * @returns Array of provider instances
   */
  public getAllProviders(): ILLMProvider[] {
    return Array.from(this.providers.values());
  }
  
  /**
   * Check if a provider is available
   * @param provider - Provider enum
   * @returns Boolean indicating if provider is available
   */
  public isProviderAvailable(provider: LLMProvider): boolean {
    return this.providers.has(provider);
  }
  
  /**
   * Register a provider (for testing or extensions)
   * @param provider - Provider enum
   * @param instance - Provider instance
   */
  public registerProvider(provider: LLMProvider, instance: ILLMProvider): void {
    this.providers.set(provider, instance);
    logger.info(`Registered provider: ${provider}`);
  }
} 