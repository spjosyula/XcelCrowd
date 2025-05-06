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
  isProduction: process.env.NODE_ENV === 'production'
};
