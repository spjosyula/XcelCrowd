import { logger } from './logger';
import { ChallengeService, challengeService } from '../services/challenge.service';
import { solutionService } from '../services/solution.service';
import { Challenge } from '../models';
import { ChallengeStatus } from '../models/interfaces';

/**
 * Scheduler utility that sets up cron jobs for time-based operations
 * Uses native Node.js setInterval to keep it lightweight with no dependencies
 */
export class Scheduler {
  private static instance: Scheduler;
  private readonly challengeService: ChallengeService;
  
  // Job intervals
  private readonly CHALLENGE_STATUS_CHECK_INTERVAL = 5 * 60 * 1000; // Check every 5 minutes
  private readonly EVALUATION_RETRY_INTERVAL = 30 * 60 * 1000; // Retry failed evaluations every 30 minutes
  
  // Job handlers
  private challengeStatusCheckInterval: NodeJS.Timeout | null = null;
  private evaluationRetryInterval: NodeJS.Timeout | null = null;
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    this.challengeService = challengeService;
  }
  
  /**
   * Get singleton instance
   * @returns Scheduler instance
   */
  public static getInstance(): Scheduler {
    if (!Scheduler.instance) {
      Scheduler.instance = new Scheduler();
    }
    return Scheduler.instance;
  }
  
  /**
   * Start all scheduled jobs
   */
  public startJobs(): void {
    logger.info('Starting scheduled jobs');
    this.startChallengeStatusCheck();
    // Add more job starters here
  }
  
  /**
   * Stop all scheduled jobs
   */
  public stopJobs(): void {
    logger.info('Stopping scheduled jobs');
    this.stopChallengeStatusCheck();
    // Add more job stoppers here
  }
  
  /**
   * Start challenge status check job
   * This job checks for challenges with passed deadlines and processes them
   */
  private startChallengeStatusCheck(): void {
    if (this.challengeStatusCheckInterval) {
      clearInterval(this.challengeStatusCheckInterval);
    }
    
    logger.info('Starting challenge status check job');
    
    // Run job immediately at startup
    this.checkAndProcessExpiredChallenges().catch(error => {
      logger.error('Error in initial challenge status check', {
        error: error instanceof Error ? error.message : String(error)
      });
    });
    
    // Schedule periodic checks
    this.challengeStatusCheckInterval = setInterval(() => {
      this.checkAndProcessExpiredChallenges().catch(error => {
        logger.error('Error in scheduled challenge status check', {
          error: error instanceof Error ? error.message : String(error)
        });
      });
    }, this.CHALLENGE_STATUS_CHECK_INTERVAL);
    
    // Prevent interval from keeping Node.js alive
    this.challengeStatusCheckInterval.unref();
  }
  
  /**
   * Stop challenge status check job
   */
  private stopChallengeStatusCheck(): void {
    if (this.challengeStatusCheckInterval) {
      clearInterval(this.challengeStatusCheckInterval);
      this.challengeStatusCheckInterval = null;
      logger.info('Stopped challenge status check job');
    }
  }
  
  /**
   * Check for challenges with passed deadlines and process them
   */
  private async checkAndProcessExpiredChallenges(): Promise<void> {
    try {
      logger.info('Running scheduled check for expired challenges');
      
      // First, update challenge statuses based on deadlines
      const statusUpdateResult = await this.challengeService.updateChallengeStatuses();
      
      logger.info('Challenge status update completed', {
        updated: statusUpdateResult.updated,
        errors: statusUpdateResult.errors
      });
      
      // If any challenges were updated to CLOSED status, process their solutions for AI evaluation
      if (statusUpdateResult.updated > 0) {
        const closedChallengeIds = statusUpdateResult.details
          .filter(detail => detail.status === ChallengeStatus.CLOSED)
          .map(detail => detail.id);
        
        logger.info('Processing solutions for AI evaluation for closed challenges', {
          count: closedChallengeIds.length,
          challengeIds: closedChallengeIds
        });
        
        // Process each challenge's solutions in sequence
        for (const challengeId of closedChallengeIds) {
          try {
            logger.info(`Processing challenge ${challengeId} for AI evaluation`);
            
            const result = await solutionService.processChallengeForArchitectReview(challengeId);
            
            logger.info(`Completed processing challenge ${challengeId}`, {
              totalSolutions: result.totalSolutions,
              processedSolutions: result.processedSolutions,
              failedSolutions: result.failedSolutions,
              processingTimeMs: result.processingTimeMs
            });
          } catch (error) {
            logger.error(`Error processing challenge ${challengeId} for AI evaluation`, {
              challengeId,
              error: error instanceof Error ? error.message : String(error)
            });
            // Continue with next challenge even if one fails
          }
        }
      } else {
        logger.info('No expired challenges to process');
      }
    } catch (error) {
      logger.error('Error checking and processing expired challenges', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
    }
  }
}

// Export singleton instance
export const scheduler = Scheduler.getInstance(); 