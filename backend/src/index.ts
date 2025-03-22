import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import hpp from 'hpp';
import { connectDB } from './utils/database';
import routes from './routes';
import { errorHandler, notFoundHandler } from './middlewares/errorhandler.middleware';
import { logger, logRequest } from './utils/logger';
import { validateEnv, config } from './utils/config';
import { xssProtection, configureCSP, enhancedCsrfProtection } from './middlewares/security.middleware';
import { studentOnlyPlatform } from './middlewares/auth.middleware';

// Validate environment variables before starting
validateEnv();

// Create Express application
export const app = express();

// Trust proxy for proper IP detection behind a reverse proxy
app.set('trust proxy', 1);

// Apply security middlewares
app.use(helmet());  // Sets security HTTP headers
app.use(configureCSP); // Content Security Policy

// Set CORS options
const corsOptions = {
  origin: config.isProduction ? config.frontendUrl : 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
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
app.use(xssProtection);   // Against XSS - using enhanced version
app.use(enhancedCsrfProtection); // CSRF protection

// Prevent parameter pollution
app.use(hpp());

// Logging
app.use(morgan('dev'));
app.use(logRequest);

// Student-only platform middleware (restricts all access to authenticated users)
app.use(studentOnlyPlatform());

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

// Handle server start with better error handling
const startServer = async () => {
  try {
    const server = app.listen(PORT, async () => {
      try {
        await connectDB();
        logger.info(`Server running in ${config.env} mode on port ${PORT}`);
      } catch (error) {
        logger.error('Failed to connect to database:', error);
        server.close(() => {
          process.exit(1);
        });
      }
    });

    // Improved error handling for the server
    server.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use. Please use another port or stop the service using this port.`);
        process.exit(1);
      } else {
        logger.error('Server error:', error);
        process.exit(1);
      }
    });

    // Request timeout handling
    server.setTimeout(30000, () => {
      logger.warn('Request timeout occurred');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (err: Error) => {
      logger.error('UNHANDLED REJECTION! 💥 Shutting down...', err);
      // Close server & exit process
      server.close(() => {
        process.exit(1);
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (err: Error) => {
      logger.error('UNCAUGHT EXCEPTION! 💥 Shutting down...', err);
      process.exit(1);
    });

    // Graceful shutdown for SIGTERM
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received. Shutting down gracefully');
      server.close(() => {
        logger.info('Process terminated');
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();