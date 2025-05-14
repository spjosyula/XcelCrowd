import 'reflect-metadata';

import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import mongoose from 'mongoose';
import { connectDB } from './utils/database';
import routes from './routes';
import { errorHandler, notFoundHandler } from './middlewares/errorhandler.middleware';
import { logger, logRequest } from './utils/logger';
import { validateEnv, config } from './config/config.env.validation';
import { xssProtection, configureCSP, enhancedCsrfProtection } from './middlewares/security.middleware';
import { authenticate, conditionalAuthenticate } from './middlewares/auth.middleware';
import swaggerUi from 'swagger-ui-express';
import { setupSwagger } from './config/swagger.config';
import { scheduler } from './utils/scheduler';
// Import the AI agent system initialization
import './services/ai';


// Validate environment variables before starting
validateEnv();

// Create Express application
export const app = express();

// Trust proxy for proper IP detection behind a reverse proxy
app.set('trust proxy', 1);

// Apply security middlewares -> ENABLE THESE FOR PRODUCTION
//app.use(helmet());  // Sets security HTTP headers
//app.use(configureCSP); // Content Security Policy

// Set CORS options
const corsOptions = {
  origin: config.isProduction ? config.frontendUrl : 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
};
app.use(cors(corsOptions));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many requests, please try again later' }
});
app.use('/api', apiLimiter);

// Request parsing
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization
app.use(mongoSanitize());  // Against NoSQL injection
app.use(xssProtection);   // Against XSS attacks
app.use(enhancedCsrfProtection); // CSRF protection

// Prevent parameter pollution
app.use(hpp());

// Logging
app.use(morgan('dev'));
app.use(logRequest);

app.use(conditionalAuthenticate);

// Swagger documentation
setupSwagger(app);


// Main routes
app.use('/api', routes);

// Base route
app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'Welcome to XcelCrowd API - Student-only platform' });
});

// Error handling
app.all('*', notFoundHandler);
app.use(errorHandler);

// Start server
const PORT = config.port;

// Database connection with retry
const connectDatabase = async (retryAttempt = 0) => {
  const maxRetries = 5;
  try {
    await connectDB();
    logger.info(`Database connected successfully`);
    return true;
  } catch (error: unknown) {
    // Properly type the error for TypeScript
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorName = error instanceof Error ? error.name : 'Unknown Error';

    logger.error(`MongoDB connection error: ${errorName}`, { error: errorMessage });
    
    if (retryAttempt < maxRetries) {
      const delay = Math.min(1000 * (2 ** retryAttempt), 30000); // Exponential backoff with 30s max
      logger.info(`Will retry connection in ${delay/1000} seconds (attempt ${retryAttempt + 1})`);
      
      setTimeout(() => {
        connectDatabase(retryAttempt + 1);
      }, delay);
    } else {
      logger.error(`Failed to connect to database after ${maxRetries} attempts.`);
      // Don't crash the server - just log the failure
    }
    return false;
  }
};

// Handle server start with better error handling
const startServer = async () => {
  try {
    const server = app.listen(PORT, () => {
      logger.info(`Server running in ${config.env} mode on port ${PORT}`);
      
      // Connect to database after server starts (don't block server startup)
      connectDatabase().catch((error: unknown) => {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Database connection failed initially, retry mechanism activated:', { error: errorMessage });
        // Don't crash the server - let the retry mechanism handle it
      });
      
      // Start scheduled jobs after server has started
      if (config.env !== 'test') { // Don't run scheduler in test environment
        scheduler.startJobs();
        logger.info('Scheduled jobs started');
      }
    });

    // Improved error handling for the server
    server.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use. Please use another port or stop the service using this port.`);
        process.exit(1);
      } else {
        logger.error('Server error:', { error: error.message });
        process.exit(1);
      }
    });

    // Request timeout handling
    server.setTimeout(30000, () => {
      logger.warn('Request timeout occurred');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (err: unknown) => {
      // Safely check error properties
      const error = err as Error;
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorName = error instanceof Error ? error.name : 'Unknown Error';
      
      // Check if it's a MongoDB connection error
      if (errorName === 'MongooseServerSelectionError' || 
          errorName === 'MongoServerSelectionError' ||
          (errorMessage && errorMessage.includes('Server selection timed out'))) {
        logger.error('MongoDB connection issue detected in unhandledRejection handler:', { error: errorMessage });
        // Don't shut down - let the retry mechanism work
      } else {
        // For other unhandled rejections, maintain existing behavior
        logger.error('UNHANDLED REJECTION! 💥 Shutting down...', { error: errorMessage });
        server.close(() => {
          process.exit(1);
        });
      }
    });

    // Add shutdown handler for scheduler
    const originalShutdown = (signal: string): Promise<void> => {
      logger.info(`${signal} received, gracefully shutting down...`);
      
      // Stop scheduled jobs
      scheduler.stopJobs();
      logger.info('Scheduled jobs stopped');
      
      // Allow pending operations to complete (within timeout)
      return mongoose.connection.close(false).then(() => {
        logger.info('MongoDB connections closed successfully');
        process.exit(0);
      }).catch((error) => {
        logger.error('Error during graceful shutdown:', error);
        process.exit(1);
      });
    };

    // Handle termination signals
    process.on('SIGTERM', () => originalShutdown('SIGTERM'));
    process.on('SIGINT', () => originalShutdown('SIGINT'));
    process.on('SIGUSR2', () => originalShutdown('SIGUSR2')); // For Nodemon restarts

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error('Failed to start server:', { error: errorMessage });
    process.exit(1);
  }
};

startServer();