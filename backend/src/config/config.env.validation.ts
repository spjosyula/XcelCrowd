/**
 * Configuration utility for validating and providing access to environment variables
 */
import { logger } from '../utils/logger';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Required environment variables
 */
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];

/**
 * Validates that all required environment variables are set
 */
export function validateEnv(): void {
  const missingVars: string[] = [];

  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      missingVars.push(varName);
    }
  });

  if (missingVars.length > 0) {
    const errorMsg = `Missing required environment variables: ${missingVars.join(', ')}`;
    logger.error(errorMsg);
    throw new Error(errorMsg);
  }

  // Log successful validation
  logger.info('Environment variables validated successfully');
}

/**
 * Application configuration derived from environment variables
 */
export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  env: process.env.NODE_ENV || 'development',
  mongodbUri: process.env.MONGODB_URI as string,
  jwtSecret: process.env.JWT_SECRET as string,
  jwtExpire: process.env.JWT_EXPIRE || '30d',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  isProduction: process.env.NODE_ENV === 'production',
  
  // AI Provider Configuration
  ai: {
    // OpenAI Configuration
    openai: {
      apiKeys: process.env.OPENAI_API_KEYS ? process.env.OPENAI_API_KEYS.split(',').map(key => key.trim()) : [],
      organizationId: process.env.OPENAI_ORGANIZATION_ID,
      defaultModel: process.env.OPENAI_DEFAULT_MODEL || 'gpt-4o',
      apiBaseUrl: process.env.OPENAI_API_BASE_URL,
      requestTimeout: parseInt(process.env.OPENAI_REQUEST_TIMEOUT || '60000', 10), // 60 seconds default
    },
    
    // Anthropic Configuration
    anthropic: {
      apiKeys: process.env.ANTHROPIC_API_KEYS ? process.env.ANTHROPIC_API_KEYS.split(',').map(key => key.trim()) : [],
      defaultModel: process.env.ANTHROPIC_DEFAULT_MODEL || 'claude-3-opus-20240229',
      apiBaseUrl: process.env.ANTHROPIC_API_BASE_URL,
      requestTimeout: parseInt(process.env.ANTHROPIC_REQUEST_TIMEOUT || '60000', 10),
    },
    
    // Azure OpenAI Configuration
    azureOpenai: {
      apiKeys: process.env.AZURE_OPENAI_API_KEYS ? process.env.AZURE_OPENAI_API_KEYS.split(',').map(key => key.trim()) : [],
      endpoint: process.env.AZURE_OPENAI_ENDPOINT,
      defaultDeployment: process.env.AZURE_OPENAI_DEFAULT_DEPLOYMENT,
      requestTimeout: parseInt(process.env.AZURE_OPENAI_REQUEST_TIMEOUT || '60000', 10),
    },
    
    // Global AI settings
    global: {
      provider: process.env.AI_DEFAULT_PROVIDER || 'openai',
      cacheEnabled: process.env.AI_CACHE_ENABLED === 'true',
      cacheTTLSeconds: parseInt(process.env.AI_CACHE_TTL_SECONDS || '3600', 10), // 1 hour default
      maxRetries: parseInt(process.env.AI_MAX_RETRIES || '3', 10),
      retryDelayMs: parseInt(process.env.AI_RETRY_DELAY_MS || '1000', 10),
      rateLimitPerMinute: parseInt(process.env.AI_RATE_LIMIT_PER_MINUTE || '60', 10),
      costTrackingEnabled: process.env.AI_COST_TRACKING_ENABLED === 'true',
    }
  }
};
