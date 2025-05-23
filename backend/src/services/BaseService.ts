import mongoose from 'mongoose';
import { ApiError } from '../utils/api.error';
import { logger } from '../utils/logger';
import { HTTP_STATUS } from '../constants';

export class BaseService {
  /**
   * Execute a function within a MongoDB transaction
   * @param operation - The async function to execute within the transaction
   * @returns The result of the operation
   */
  protected async withTransaction<T>(
    operation: (session: mongoose.ClientSession) => Promise<T>,
    options: {
      isolationLevel?: mongoose.mongo.ReadConcernLevel
    } = {}
  ): Promise<T> {
    const session = await mongoose.startSession();
    
    // Fix the type issue by using the correct option format
    const transactionOptions: mongoose.mongo.TransactionOptions = {
      readPreference: 'primary',
      readConcern: { level: options.isolationLevel || 'majority' },
      writeConcern: undefined
    };
    
    // Use proper type for writeConcern - use numeric value instead of string
    if (process.env.NODE_ENV === 'production') {
      // In production, ensure majority write concern for consistency
      transactionOptions.writeConcern = { w: 'majority' };
    }
    
    session.startTransaction(transactionOptions);

    try {
      const result = await operation(session);
      await session.commitTransaction();
      return result;
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Transaction error:`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      if (error instanceof Error && 'code' in error) {
        const mongoError = error as unknown as { code: number; codeName?: string };
        if (mongoError.code === 112) {
          throw ApiError.conflict('Operation failed due to a write conflict. Please try again.');
        }
      }
      
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR, 
        'Database transaction failed',
        true,
        'TRANSACTION_FAILURE'
      );
    } finally {
      session.endSession();
    }
  }
}