// src/lib/database.ts
import mongoose from 'mongoose';
import { logger } from './logger';
import { config } from './config';

// Connection options with improved pooling settings
const connectionOptions: mongoose.ConnectOptions = {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  // Add connection pooling configuration
  maxPoolSize: 10, // Maximum number of connections in the pool
  minPoolSize: 2, // Minimum number of connections maintained in the pool
  maxIdleTimeMS: 30000, // How long a connection can be idle before being closed
};

/**
 * Database connection state type
 */
type ConnectionState = {
  isConnected: boolean | number;
};

/**
 * Singleton to track the connection state
 */
const connection: ConnectionState = {
  isConnected: false
};

/**
 * Connect to MongoDB
 */
export async function connectDB(): Promise<void> {
  if (connection.isConnected) {
    logger.info('Using existing database connection');
    return;
  }

  // Get environment variables
  const dbUri = config.mongodbUri;
  
  if (!dbUri) {
    throw new Error('MongoDB connection string is not defined');
  }

  try {
    logger.info('Connecting to MongoDB...');
    const db = await mongoose.connect(dbUri, connectionOptions);
    
    connection.isConnected = db.connections[0].readyState;
    
    logger.info(`MongoDB connected: ${db.connection.host}`);
    
    // Set up connection event handlers
    mongoose.connection.on('error', (err) => {
      logger.error(`MongoDB connection error: ${err}`);
    });
    
    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
      // Attempt reconnection after a delay if not in test mode
      if (config.env !== 'test') {
        setTimeout(() => {
          logger.info('Attempting to reconnect to MongoDB...');
          connectDB();
        }, 5000);
      }
    });
    
    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('MongoDB connection closed through app termination');
      process.exit(0);
    });
    
  } catch (error) {
    logger.error(`Error connecting to database: ${error}`);
    throw error;
  }
}

/**
 * Disconnect from MongoDB
 */
export async function disconnectDB(): Promise<void> {
  if (!connection.isConnected) {
    return;
  }
  
  if (config.isProduction) {
    await mongoose.disconnect();
    connection.isConnected = false;
    logger.info('MongoDB disconnected');
  }
}
  
// Export mongoose for direct access if needed
export { mongoose };