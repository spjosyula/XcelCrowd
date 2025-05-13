import { logger } from './logger';
import { ChallengeService, challengeService } from '../services/challenge.service';
import { Challenge } from '../models';
import { ChallengeStatus } from '../models/interfaces';
import mongoose from 'mongoose';
import cron, { ScheduledTask } from 'node-cron';
import { EventEmitter } from 'events';

/**
 * Scheduler utility that sets up cron jobs for time-based operations
 * Uses native Node.js setInterval to keep it lightweight with no dependencies
 */
export class Scheduler extends EventEmitter {
  private static instance: Scheduler;
  private readonly challengeService: ChallengeService;
  
  // Event names
  public static readonly EVENTS = {
    CHALLENGE_DEADLINE_REACHED: 'challenge:deadline:reached',
    EVALUATION_COMPLETE: 'evaluation:complete'
  };
  
  // Job intervals
  private readonly CHALLENGE_STATUS_CHECK_INTERVAL = 5 * 60 * 1000; // Check every 5 minutes
  
  // Job handlers
  private challengeStatusCheckInterval: NodeJS.Timeout | null = null;
  
  // Map to store timers for upcoming challenge deadlines
  private challengeDeadlineTimers: Map<string, NodeJS.Timeout> = new Map();
  
  private jobs: Map<string, ScheduledTask>;
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    super();
    this.challengeService = challengeService;
    this.jobs = new Map();
    this.initializeJobs();
    this.setupEventListeners();
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
    this.scheduleDeadlinesForAllActiveChallenges();
    // Add more job starters here
  }
  
  /**
   * Stop all scheduled jobs
   */
  public stopJobs(): void {
    logger.info('Stopping scheduled jobs');
    this.stopChallengeStatusCheck();
    this.clearAllDeadlineTimers();
    // Add more job stoppers here
  }

  /**
   * Set up event listeners for the scheduler's events
   */
  private setupEventListeners(): void {
    // Handle challenge deadline reached events
    this.on(Scheduler.EVENTS.CHALLENGE_DEADLINE_REACHED, async (challengeId: string) => {
      try {
        logger.info(`Event received: Challenge deadline reached for ${challengeId}`);
        await this.processChallengeDeadline(challengeId);
      } catch (error) {
        logger.error(`Error handling deadline reached event for challenge ${challengeId}`, {
          challengeId,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    });
  }
  
  /**
   * Schedule precise timers for all active challenges
   * This creates dedicated timers that will fire exactly when each challenge deadline is reached
   */
  private async scheduleDeadlinesForAllActiveChallenges(): Promise<void> {
    try {
      // First clear any existing timers
      this.clearAllDeadlineTimers();
      
      logger.info('Scheduling precise deadline timers for all active challenges');
      
      // Check database connection first
      if (mongoose.connection.readyState !== 1) {
        logger.warn('Database connection not ready, skipping deadline scheduling');
        return;
      }
      
      // Get all active challenges with future deadlines
      const now = new Date();
      const activeChallenges = await Challenge.find({
        status: ChallengeStatus.ACTIVE,
        deadline: { $gt: now }
      });
      
      logger.info(`Found ${activeChallenges.length} active challenges with upcoming deadlines to schedule`);
      
      // Create a timer for each challenge
      for (const challenge of activeChallenges) {
        this.scheduleDeadlineTimer(challenge);
      }
    } catch (error) {
      logger.error('Error scheduling challenge deadlines', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
    }
  }
  
  /**
   * Schedule a precise timer for a single challenge deadline
   * @param challenge - The challenge to schedule a deadline timer for
   */
  private scheduleDeadlineTimer(challenge: any): void {
    try {
      const challengeId = (challenge._id as mongoose.Types.ObjectId).toString();
      const deadline = new Date(challenge.deadline);
      const now = new Date();
      
      // Calculate milliseconds until deadline
      const msUntilDeadline = deadline.getTime() - now.getTime();
      
      if (msUntilDeadline <= 0) {
        logger.warn(`Challenge ${challengeId} deadline has already passed, not scheduling timer`);
        return;
      }
      
      // Clear any existing timer for this challenge
      if (this.challengeDeadlineTimers.has(challengeId)) {
        clearTimeout(this.challengeDeadlineTimers.get(challengeId)!);
        this.challengeDeadlineTimers.delete(challengeId);
      }
      
      logger.info(`Scheduling precise deadline timer for challenge ${challengeId}`, {
        challengeId,
        title: challenge.title,
        deadline: challenge.deadline,
        msUntilDeadline,
        hoursUntilDeadline: (msUntilDeadline / (1000 * 60 * 60)).toFixed(2)
      });
      
      // Create a timer that will fire exactly when the deadline is reached
      const timer = setTimeout(() => {
        try {
          logger.info(`🚨 Challenge deadline reached for ${challengeId}`, {
            challengeId,
            title: challenge.title,
            deadline: challenge.deadline
          });
          
          // Remove from map
          this.challengeDeadlineTimers.delete(challengeId);
          
          // Emit event instead of directly processing
          this.emit(Scheduler.EVENTS.CHALLENGE_DEADLINE_REACHED, challengeId);
        } catch (error) {
          logger.error(`Error processing challenge ${challengeId} deadline`, {
            challengeId,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }, msUntilDeadline);
      
      // Don't let this timer prevent Node.js from exiting
      timer.unref();
      
      // Store the timer reference
      this.challengeDeadlineTimers.set(challengeId, timer);
    } catch (error) {
      logger.error(`Error scheduling timer for challenge`, {
        challengeId: challenge._id?.toString(),
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  
  /**
   * Clear all scheduled deadline timers
   */
  private clearAllDeadlineTimers(): void {
    logger.info(`Clearing ${this.challengeDeadlineTimers.size} challenge deadline timers`);
    
    // Clear all scheduled timers
    for (const [challengeId, timer] of this.challengeDeadlineTimers.entries()) {
      clearTimeout(timer);
      logger.debug(`Cleared deadline timer for challenge ${challengeId}`);
    }
    
    // Reset the map
    this.challengeDeadlineTimers.clear();
  }
  
  /**
   * Process a single challenge when its deadline is reached
   * @param challengeId - The ID of the challenge whose deadline has been reached
   */
  private async processChallengeDeadline(challengeId: string): Promise<void> {
    try {
      logger.info(`Processing deadline reached for challenge ${challengeId}`);
      
      // Check database connection first
      if (mongoose.connection.readyState !== 1) {
        logger.warn('Database connection not ready, skipping challenge processing');
        return;
      }
      
      // Fetch the latest challenge data
      const challenge = await Challenge.findById(challengeId);
      
      if (!challenge) {
        logger.warn(`Challenge ${challengeId} not found, cannot process deadline`);
        return;
      }
      
      if (challenge.status !== ChallengeStatus.ACTIVE) {
        logger.warn(`Challenge ${challengeId} is not active (status: ${challenge.status}), skipping deadline processing`);
        return;
      }
      
      // Update challenge status
      challenge.status = ChallengeStatus.CLOSED;
      await challenge.save();
      
      logger.info(`Challenge ${challengeId} status updated to CLOSED, services will process via events`);
      
      // The services (AIEvaluationService and SolutionService) are now listening for the event
      // and will process the challenge accordingly when they receive it.
      // No need to call them directly here.
    } catch (error) {
      logger.error(`Error processing challenge deadline`, {
        challengeId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
    }
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
    
    // Schedule periodic checks - this serves as a backup mechanism
    // to the precise deadline timers, ensuring no deadlines are missed
    this.challengeStatusCheckInterval = setInterval(() => {
      this.checkAndProcessExpiredChallenges().catch(error => {
        logger.error('Error in scheduled challenge status check', {
          error: error instanceof Error ? error.message : String(error)
        });
      });
      
      // Also refresh the deadline timers for any newly created challenges
      this.scheduleDeadlinesForAllActiveChallenges().catch(error => {
        logger.error('Error refreshing challenge deadline timers', {
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
   * This is a redundancy mechanism to complement the precise deadline timers
   */
  private async checkAndProcessExpiredChallenges(): Promise<void> {
    try {
      logger.info('Running scheduled check for expired challenges');

      // Check database connection first
      if (mongoose.connection.readyState !== 1) {
        logger.warn('Database connection not ready, skipping challenge status check');
        return;
      }
      
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
            // Check if we already processed this challenge via the precise deadline timer
            if (this.challengeDeadlineTimers.has(challengeId)) {
              logger.info(`Challenge ${challengeId} already has a deadline timer, skipping redundant processing`);
              continue;
            }
            
            logger.info(`Emitting deadline reached event for challenge ${challengeId}`);
            
            // Emit event instead of directly processing
            this.emit(Scheduler.EVENTS.CHALLENGE_DEADLINE_REACHED, challengeId);
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

  private initializeJobs(): void {
    // Check for challenges with deadlines passing every hour
    this.registerJob('process-challenge-deadlines', '0 * * * *', this.processDeadlines.bind(this));
    
    // Add more scheduled jobs here as needed
  }

  /**
   * Register a new cron job
   * @param name - Unique identifier for the job
   * @param schedule - Cron schedule expression
   * @param task - Function to execute
   */
  public registerJob(name: string, schedule: string, task: () => Promise<void>): void {
    if (this.jobs.has(name)) {
      this.jobs.get(name)?.stop();
      logger.info(`Stopping previous job: ${name}`);
    }

    const job = cron.schedule(schedule, async () => {
      try {
        logger.info(`Running scheduled job: ${name}`);
        await task();
        logger.info(`Completed scheduled job: ${name}`);
      } catch (error) {
        logger.error(`Error in scheduled job ${name}:`, {
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        });
      }
    }, {
      timezone: 'UTC'
    });

    this.jobs.set(name, job);
    logger.info(`Registered scheduled job: ${name} with schedule: ${schedule}`);
  }

  /**
   * Check for challenges with deadlines passing and process evaluations
   * Legacy method kept for backward compatibility, primarily using precise timers now
   */
  private async processDeadlines(): Promise<void> {
    try {
      const now = new Date();
      
      // This hourly check is now a backup for the precise deadline timers
      logger.info('Running hourly backup check for missed challenge deadlines');
      
      // Find challenges with deadlines that just passed (within the last hour)
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      
      const deadlineChallenges = await Challenge.find({
        status: ChallengeStatus.ACTIVE,
        deadline: {
          $gte: oneHourAgo,
          $lte: now
        }
      });
      
      logger.info(`Found ${deadlineChallenges.length} challenges with deadlines just passed (backup check)`);
      
      // Process each challenge
      for (const challenge of deadlineChallenges) {
        const challengeId = (challenge._id as mongoose.Types.ObjectId).toString();
        
        // Skip if we already have a timer for this challenge (it will be processed by the timer)
        if (this.challengeDeadlineTimers.has(challengeId)) {
          logger.info(`Challenge ${challengeId} already has a deadline timer, skipping duplicate processing`);
          continue;
        }
        
        logger.info(`Emitting deadline reached event for challenge ${challengeId} (from hourly check)`);
        
        // Emit event instead of directly processing
        this.emit(Scheduler.EVENTS.CHALLENGE_DEADLINE_REACHED, challengeId);
      }
      
      // Refresh all deadline timers to catch any newly created challenges
      await this.scheduleDeadlinesForAllActiveChallenges();
    } catch (error) {
      logger.error(`Error in processDeadlines job`, {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
    }
  }
}

// Export singleton instance
export const scheduler = Scheduler.getInstance(); 