import mongoose from 'mongoose';
import { logger } from './logger';
import { config } from './config';

/**
 * Connection state tracking
 */
type ConnectionState = {
  isConnected: boolean | number;
  retryCount: number;
  isConnecting: boolean;
  connectionPromise: Promise<void> | null;
};

/**
 * Singleton connection state tracker
 */
const connection: ConnectionState = {
  isConnected: false,
  retryCount: 0,
  isConnecting: false,
  connectionPromise: null
};

/**
 * Advanced connection options with production-ready settings
 */
const connectionOptions: mongoose.ConnectOptions = {
  // Connection timeouts
  serverSelectionTimeoutMS: 10000,    // How long to try selecting a server
  connectTimeoutMS: 30000,            // How long to wait for initial connection
  socketTimeoutMS: 45000,             // How long to wait for operations
  
  // Connection pooling
  maxPoolSize: 50,                    // Maximum connections in the pool (adjust based on expected load)
  minPoolSize: 5,                     // Minimum connections maintained in the pool
  maxIdleTimeMS: 60000,               // How long a connection can be idle before closing
  
  // Write concern for data durability
  writeConcern: {
    w: 'majority',                    // Ensures writes propagate to majority of nodes
    j: true,                          // Waits for write to be committed to journal
    wtimeout: 5000                    // How long to wait for write concern
  },
  
  // Additional options
  heartbeatFrequencyMS: 10000,        // How often to check server status
  autoIndex: config.isProduction ? false : true, // Disable auto-indexing in production
  autoCreate: config.isProduction ? false : true, // Disable auto collection creation in production
};

/**
 * Exponential backoff calculation for reconnection attempts
 */
const getRetryDelay = (retryCount: number): number => {
  const baseDelay = 1000; // 1 second
  const maxDelay = 60000; // 1 minute
  
  // Exponential backoff with jitter
  const exponentialDelay = Math.min(
    maxDelay,
    baseDelay * Math.pow(2, retryCount) * (0.8 + Math.random() * 0.4)
  );
  
  return exponentialDelay;
};

/**
 * Connect to MongoDB with advanced retry and connection management
 */
export async function connectDB(): Promise<void> {
  const dbUri = config.mongodbUri;
  
  if (!dbUri) {
    throw new Error('MongoDB connection string is not defined');
  }

  // Return existing connection if active
  if (connection.isConnected) {
    logger.debug('Using existing database connection');
    return;
  }
  
  // Return in-progress connection attempt if one exists
  if (connection.isConnecting && connection.connectionPromise) {
    logger.debug('Connection already in progress, waiting...');
    return connection.connectionPromise;
  }
  
  // Start new connection attempt
  connection.isConnecting = true;
  connection.connectionPromise = (async () => {
    try {
      logger.info(`Connecting to MongoDB (attempt ${connection.retryCount + 1})...`);
      
      // Establish connection
      const db = await mongoose.connect(dbUri, connectionOptions);
      
      connection.isConnected = db.connections[0].readyState;
      connection.retryCount = 0;
      
      logger.info(`MongoDB connected: ${db.connection.host}`);
      
      // Set up connection monitoring and events
      setupConnectionMonitoring();
      
      return;
    } catch (error) {
      logger.error(`MongoDB connection error: ${error}`);
      
      // Increment retry counter
      connection.retryCount++;
      
      // Calculate delay for next retry
      const retryDelay = getRetryDelay(connection.retryCount);
      
      logger.info(`Will retry connection in ${retryDelay/1000} seconds (attempt ${connection.retryCount})`);
      
      // Schedule reconnection
      setTimeout(() => {
        connection.isConnecting = false;
        connection.connectionPromise = null;
        connectDB();
      }, retryDelay);
      
      throw error;
    } finally {
      connection.isConnecting = false;
      connection.connectionPromise = null;
    }
  })();
  
  return connection.connectionPromise;
}

/**
 * Setup connection monitoring and event handlers
 */
function setupConnectionMonitoring(): void {
  mongoose.connection.on('error', (err) => {
    logger.error(`MongoDB connection error: ${err}`);
  });
  
  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected');
    connection.isConnected = false;
    
    // Attempt reconnection after a delay if not in test mode
    // and not already reconnecting
    if (config.env !== 'test' && !connection.isConnecting) {
      const retryDelay = getRetryDelay(connection.retryCount);
      logger.info(`Attempting to reconnect to MongoDB in ${retryDelay/1000} seconds...`);
      
      setTimeout(() => {
        connectDB();
      }, retryDelay);
    }
  });
  
  mongoose.connection.on('reconnected', () => {
    logger.info('MongoDB reconnected');
    connection.isConnected = true;
    connection.retryCount = 0;
  });
  
  // Periodic connection health check
  if (config.isProduction) {
    setInterval(async () => {
      try {
        if (connection.isConnected && mongoose.connection.db) {
          // Simple ping to verify connection health
          await mongoose.connection.db.admin().ping();
          logger.debug('MongoDB connection healthy');
        }
      } catch (error) {
        logger.error('MongoDB health check failed', error);
        // Force disconnect to trigger reconnection
        await mongoose.connection.close(true);
      }
    }, 30000); // Every 30 seconds
  }
}

/**
 * Gracefully disconnect from MongoDB
 */
export async function disconnectDB(): Promise<void> {
  if (!connection.isConnected) {
    return;
  }
  
  try {
    logger.info('Disconnecting from MongoDB...');
    await mongoose.disconnect();
    connection.isConnected = false;
    logger.info('MongoDB disconnected successfully');
  } catch (error) {
    logger.error(`Error disconnecting from MongoDB: ${error}`);
    throw error;
  }
}

/**
 * Setup process signal handlers for graceful shutdown
 */
export function setupGracefulShutdown(): void {
  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received, gracefully shutting down...`);
    try {
      // Allow pending operations to complete (within timeout)
      await mongoose.connection.close(false);
      logger.info('MongoDB connections closed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  };

  // Handle termination signals
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGUSR2', () => shutdown('SIGUSR2')); // For Nodemon restarts
}

// Export mongoose for direct access if needed
export { mongoose };