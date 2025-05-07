import { Types } from 'mongoose';
import { Solution, Challenge } from '../models';
import { logger } from '../utils/logger';
import { ApiError } from '../utils/api.error';
import {
  SolutionStatus,
  ChallengeStatus,
  EvaluationDecision,
  HTTP_STATUS
} from '../models/interfaces';
import { BaseService } from './BaseService';
import { evaluationPipelineController } from './ai/EvaluationPipelineController';
import { MongoSanitizer } from '../utils/mongo.sanitize';

/**
 * Interface for architect dashboard metrics
 */
export interface IArchitectDashboardMetrics {
  queue: {
    pendingChallenges: number;
    claimedChallenges: number;
    pendingSolutions: number;
    underReviewSolutions: number;
    completedSolutions: number;
    averageReviewTime: number; // in milliseconds
  };
  performance: {
    approvalRate: number;
    rejectionRate: number;
    averageScore: number;
    totalReviewed: number;
  };
  activity: {
    today: number;
    thisWeek: number;
    thisMonth: number;
  };
  insights: {
    topChallengeCategories: Array<{ category: string, count: number }>;
    submissionTrends: Array<{ date: string, count: number }>;
    aiDecisionAlignment: number; // percentage of architect decisions matching AI recommendations
  };
}

/**
 * Interface for student dashboard stats
 */
export interface IStudentDashboardStats {
  submissions: {
    total: number;
    pending: number;
    approved: number;
    rejected: number;
    inReview: number;
  };
  performance: {
    averageScore: number;
    highestScore: number;
    completionRate: number;
  };
  activity: {
    recent: Array<{
      id: string;
      challengeTitle: string;
      submissionDate: Date;
      status: string;
      score?: number;
    }>;
  };
}

/**
 * Interface for company dashboard stats
 */
export interface ICompanyDashboardStats {
  challenges: {
    total: number;
    active: number;
    closed: number;
    draft: number;
  };
  engagement: {
    totalSubmissions: number;
    averageSubmissionsPerChallenge: number;
    topChallenges: Array<{
      id: string;
      title: string;
      submissionCount: number;
    }>;
  };
  solutions: {
    selected: number;
    rejected: number;
    pending: number;
  };
}

/**
 * Dashboard Service for architect-specific metrics and analytics
 */
export class DashboardService extends BaseService {
  /**
   * Get comprehensive metrics for architect dashboard
   * @param architectId - ID of the architect
   * @returns Dashboard metrics
   */
  async getArchitectDashboardMetrics(architectId: string): Promise<IArchitectDashboardMetrics> {
    try {
      // Validate architectId
      const sanitizedArchitectId = MongoSanitizer.validateObjectId(architectId, 'architect');

      // Calculate today, this week, and this month date ranges
      const now = new Date();
      const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - now.getDay()); // Start of week (Sunday)
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

      // Run aggregation pipelines in parallel for efficiency
      const [
        queueMetrics,
        performanceMetrics,
        activityMetrics,
        categoryMetrics,
        trendMetrics,
        alignmentMetrics
      ] = await Promise.all([
        // Queue metrics
        this.getQueueMetrics(sanitizedArchitectId),

        // Performance metrics
        this.getPerformanceMetrics(sanitizedArchitectId),

        // Activity metrics
        this.getActivityMetrics(sanitizedArchitectId, todayStart, weekStart, monthStart),

        // Top challenge categories
        this.getTopChallengeCategories(sanitizedArchitectId),

        // Submission trends (last 14 days)
        this.getSubmissionTrends(),

        // AI decision alignment
        this.getAIDecisionAlignment(sanitizedArchitectId)
      ]);

      // Combine all metrics into a single response
      return {
        queue: queueMetrics,
        performance: performanceMetrics,
        activity: activityMetrics,
        insights: {
          topChallengeCategories: categoryMetrics,
          submissionTrends: trendMetrics,
          aiDecisionAlignment: alignmentMetrics
        }
      };
    } catch (error) {
      logger.error(`Error getting architect dashboard metrics`, {
        architectId,
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve dashboard metrics',
        true,
        'DASHBOARD_METRICS_ERROR'
      );
    }
  }

  /**
   * Get queue metrics
   * @param architectId Architect ID
   * @returns Queue metrics
   */
  private async getQueueMetrics(architectId: string): Promise<IArchitectDashboardMetrics['queue']> {
    // Calculate queue metrics using aggregation
    const [challengeAggregation, solutionAggregation, timeAggregation] = await Promise.all([
      // Challenge aggregation
      Challenge.aggregate([
        {
          $facet: {
            // Pending challenges (not claimed by anyone)
            pending: [
              {
                $match: {
                  status: ChallengeStatus.CLOSED,
                  claimedBy: { $exists: false }
                }
              },
              { $count: 'count' }
            ],
            // Claimed by this architect
            claimed: [
              {
                $match: {
                  claimedBy: new Types.ObjectId(architectId)
                }
              },
              { $count: 'count' }
            ]
          }
        }
      ]),

      // Solution aggregation
      Solution.aggregate([
        {
          $facet: {
            // Pending solutions
            pending: [
              { $match: { status: SolutionStatus.SUBMITTED } },
              { $count: 'count' }
            ],
            // Under review by this architect
            underReview: [
              {
                $match: {
                  status: SolutionStatus.UNDER_REVIEW,
                  reviewedBy: new Types.ObjectId(architectId)
                }
              },
              { $count: 'count' }
            ],
            // Completed by this architect
            completed: [
              {
                $match: {
                  reviewedBy: new Types.ObjectId(architectId),
                  $or: [
                    { status: SolutionStatus.APPROVED },
                    { status: SolutionStatus.REJECTED }
                  ]
                }
              },
              { $count: 'count' }
            ]
          }
        }
      ]),

      // Average review time calculation
      Solution.aggregate([
        {
          $match: {
            reviewedBy: new Types.ObjectId(architectId),
            reviewedAt: { $exists: true },
            $or: [
              { status: SolutionStatus.APPROVED },
              { status: SolutionStatus.REJECTED }
            ]
          }
        },
        {
          $project: {
            reviewTime: {
              $subtract: [
                '$reviewedAt',
                '$updatedAt' // Using updatedAt as a proxy for when the solution went under review
              ]
            }
          }
        },
        {
          $group: {
            _id: null,
            averageTime: { $avg: '$reviewTime' }
          }
        }
      ])
    ]);

    // Extract values from aggregation results
    return {
      pendingChallenges: challengeAggregation[0].pending[0]?.count || 0,
      claimedChallenges: challengeAggregation[0].claimed[0]?.count || 0,
      pendingSolutions: solutionAggregation[0].pending[0]?.count || 0,
      underReviewSolutions: solutionAggregation[0].underReview[0]?.count || 0,
      completedSolutions: solutionAggregation[0].completed[0]?.count || 0,
      averageReviewTime: timeAggregation[0]?.averageTime || 0
    };
  }

  /**
   * Get performance metrics
   * @param architectId Architect ID
   * @returns Performance metrics
   */
  private async getPerformanceMetrics(architectId: string): Promise<IArchitectDashboardMetrics['performance']> {
    const aggregationResult = await Solution.aggregate([
      {
        $match: {
          reviewedBy: new Types.ObjectId(architectId),
          $or: [
            { status: SolutionStatus.APPROVED },
            { status: SolutionStatus.REJECTED }
          ]
        }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          avgScore: {
            $avg: {
              $cond: [
                { $eq: ['$status', SolutionStatus.APPROVED] },
                '$score',
                0
              ]
            }
          }
        }
      },
      {
        $facet: {
          approved: [
            { $match: { _id: SolutionStatus.APPROVED } },
            { $project: { count: 1, avgScore: 1 } }
          ],
          rejected: [
            { $match: { _id: SolutionStatus.REJECTED } },
            { $project: { count: 1 } }
          ],
          total: [
            { $group: { _id: null, total: { $sum: '$count' } } }
          ]
        }
      }
    ]);

    const approvedCount = aggregationResult[0].approved[0]?.count || 0;
    const rejectedCount = aggregationResult[0].rejected[0]?.count || 0;
    const totalCount = approvedCount + rejectedCount;

    return {
      approvalRate: totalCount > 0 ? approvedCount / totalCount : 0,
      rejectionRate: totalCount > 0 ? rejectedCount / totalCount : 0,
      averageScore: aggregationResult[0].approved[0]?.avgScore || 0,
      totalReviewed: totalCount
    };
  }

  /**
   * Get activity metrics
   * @param architectId Architect ID
   * @param todayStart Start of today
   * @param weekStart Start of week
   * @param monthStart Start of month
   * @returns Activity metrics
   */
  private async getActivityMetrics(
    architectId: string,
    todayStart: Date,
    weekStart: Date,
    monthStart: Date
  ): Promise<IArchitectDashboardMetrics['activity']> {
    const aggregationResult = await Solution.aggregate([
      {
        $match: {
          reviewedBy: new Types.ObjectId(architectId),
          reviewedAt: { $exists: true }
        }
      },
      {
        $facet: {
          today: [
            { $match: { reviewedAt: { $gte: todayStart } } },
            { $count: 'count' }
          ],
          thisWeek: [
            { $match: { reviewedAt: { $gte: weekStart } } },
            { $count: 'count' }
          ],
          thisMonth: [
            { $match: { reviewedAt: { $gte: monthStart } } },
            { $count: 'count' }
          ]
        }
      }
    ]);

    return {
      today: aggregationResult[0].today[0]?.count || 0,
      thisWeek: aggregationResult[0].thisWeek[0]?.count || 0,
      thisMonth: aggregationResult[0].thisMonth[0]?.count || 0
    };
  }

  /**
   * Get top challenge categories
   * @param architectId Architect ID
   * @returns Top challenge categories with counts
   */
  private async getTopChallengeCategories(architectId: string): Promise<Array<{ category: string, count: number }>> {
    // Get challenges claimed by this architect
    const challenges = await Challenge.aggregate([
      {
        $match: {
          claimedBy: new Types.ObjectId(architectId)
        }
      },
      {
        $unwind: '$category'
      },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 5
      },
      {
        $project: {
          _id: 0,
          category: '$_id',
          count: 1
        }
      }
    ]);

    return challenges;
  }

  /**
   * Get submission trends for the last 14 days
   * @returns Submission trends by date
   */
  private async getSubmissionTrends(): Promise<Array<{ date: string, count: number }>> {
    // Calculate date range (last 14 days)
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 14);

    // Get submission counts by date
    const trends = await Solution.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      },
      {
        $project: {
          _id: 0,
          date: '$_id',
          count: 1
        }
      }
    ]);

    return trends;
  }

  /**
   * Get AI decision alignment metric
   * @param architectId Architect ID
   * @returns AI decision alignment percentage
   */
  private async getAIDecisionAlignment(architectId: string): Promise<number> {
    // Find solutions reviewed by this architect that have AI evaluation results
    const solutions = await Solution.find({
      reviewedBy: new Types.ObjectId(architectId),
      $or: [
        { status: SolutionStatus.APPROVED },
        { status: SolutionStatus.REJECTED }
      ],
      'context.pipelineResults.scoringFeedback': { $exists: true }
    }).lean();

    if (solutions.length === 0) {
      return 0;
    }

    // Calculate alignment between AI and architect decisions
    let alignedDecisions = 0;

    for (const solution of solutions) {
      if (solution.context?.pipelineResults?.scoringFeedback) {
        // Get AI decision
        const aiDecision = solution.context.pipelineResults.scoringFeedback.decision;

        // Get architect decision
        const architectDecision = solution.status === SolutionStatus.APPROVED
          ? EvaluationDecision.PASS
          : EvaluationDecision.FAIL;

        // Check alignment
        if (
          (aiDecision === EvaluationDecision.PASS && architectDecision === EvaluationDecision.PASS) ||
          (aiDecision === EvaluationDecision.FAIL && architectDecision === EvaluationDecision.FAIL) ||
          // Count REVIEW as aligned with either PASS or FAIL since it indicates human judgment needed
          (aiDecision === EvaluationDecision.REVIEW)
        ) {
          alignedDecisions++;
        }
      }
    }

    return solutions.length > 0 ? alignedDecisions / solutions.length : 0;
  }

  /**
   * Get solution analytics with AI evaluation details
   * @param solutionId Solution ID
   * @returns Solution with detailed analytics
   */
  async getSolutionAnalytics(solutionId: string): Promise<{
    solution: any;
    aiEvaluation: {
      spamFiltering: any;
      requirementsCompliance: any;
      codeQuality: any;
      scoringFeedback: any;
      metrics: any;
    };
    architectReview: any;
  }> {
    try {
      // Validate and sanitize solutionId
      const sanitizedSolutionId = MongoSanitizer.validateObjectId(solutionId, 'solution');

      // Get solution with populated references
      const solution = await Solution.findById(sanitizedSolutionId)
        .populate('challenge')
        .populate('student')
        .populate('reviewedBy')
        .lean();

      if (!solution) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Solution not found',
          true,
          'SOLUTION_NOT_FOUND'
        );
      }

      // Extract AI evaluation details
      const aiEvaluation = {
        spamFiltering: solution.context?.pipelineResults?.spamFiltering || null,
        requirementsCompliance: solution.context?.pipelineResults?.requirementsCompliance || null,
        codeQuality: solution.context?.pipelineResults?.codeQuality || null,
        scoringFeedback: solution.context?.pipelineResults?.scoringFeedback || null,
        metrics: solution.context?.pipelineResults
          ? evaluationPipelineController.getMetricsFromResults(solution.context.pipelineResults)
          : null
      };

      // Extract architect review details
      const architectReview = {
        status: solution.status,
        feedback: solution.feedback,
        score: solution.score,
        reviewedAt: solution.reviewedAt,
        reviewedBy: solution.reviewedBy
      };

      return {
        solution,
        aiEvaluation,
        architectReview
      };
    } catch (error) {
      logger.error(`Error getting solution analytics`, {
        solutionId,
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve solution analytics',
        true,
        'SOLUTION_ANALYTICS_ERROR'
      );
    }
  }

  /**
 * Get comprehensive dashboard statistics for a student
 * @param studentId - ID of the student
 * @returns Dashboard statistics
 */
  async getStudentDashboardStats(studentId: string): Promise<IStudentDashboardStats> {
    try {
      // Validate studentId
      const sanitizedStudentId = MongoSanitizer.validateObjectId(studentId, 'student');

      // Get all of this student's solutions
      const solutionAggregate = await Solution.aggregate([
        {
          $match: {
            student: new Types.ObjectId(sanitizedStudentId)
          }
        },
        {
          $facet: {
            // Count solutions by status
            statusCounts: [
              {
                $group: {
                  _id: '$status',
                  count: { $sum: 1 }
                }
              }
            ],
            // Performance metrics
            performance: [
              {
                $group: {
                  _id: null,
                  avgScore: { $avg: '$score' },
                  maxScore: { $max: '$score' },
                  total: { $sum: 1 },
                  completed: {
                    $sum: {
                      $cond: [
                        { $in: ['$status', [SolutionStatus.APPROVED, SolutionStatus.REJECTED]] },
                        1,
                        0
                      ]
                    }
                  }
                }
              }
            ],
            // Recent activity
            recent: [
              {
                $sort: { createdAt: -1 }
              },
              {
                $limit: 5
              },
              {
                $lookup: {
                  from: 'challenges',
                  localField: 'challenge',
                  foreignField: '_id',
                  as: 'challengeDetails'
                }
              },
              {
                $project: {
                  id: '$_id',
                  challengeTitle: { $arrayElemAt: ['$challengeDetails.title', 0] },
                  submissionDate: '$createdAt',
                  status: '$status',
                  score: '$score'
                }
              }
            ]
          }
        }
      ]);

      // Process solution counts by status
      const statusCounts = solutionAggregate[0].statusCounts.reduce((acc: Record<string, number>, curr: any) => {
        acc[curr._id] = curr.count;
        return acc;
      }, {});

      const performance = solutionAggregate[0].performance[0] || {
        avgScore: 0,
        maxScore: 0,
        total: 0,
        completed: 0
      };

      return {
        submissions: {
          total: performance.total,
          pending: statusCounts[SolutionStatus.SUBMITTED] || 0,
          approved: statusCounts[SolutionStatus.APPROVED] || 0,
          rejected: statusCounts[SolutionStatus.REJECTED] || 0,
          inReview: statusCounts[SolutionStatus.UNDER_REVIEW] || 0
        },
        performance: {
          averageScore: performance.avgScore || 0,
          highestScore: performance.maxScore || 0,
          completionRate: performance.total > 0 ? performance.completed / performance.total : 0
        },
        activity: {
          recent: solutionAggregate[0].recent || []
        }
      };
    } catch (error) {
      logger.error(`Error getting student dashboard stats`, {
        studentId,
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve student dashboard statistics',
        true,
        'DASHBOARD_STATS_ERROR'
      );
    }
  }

  /**
   * Get comprehensive dashboard statistics for a company
   * @param companyId - ID of the company
   * @returns Dashboard statistics
   */
  async getCompanyDashboardStats(companyId: string): Promise<ICompanyDashboardStats> {
    try {
      // Validate companyId
      const sanitizedCompanyId = MongoSanitizer.validateObjectId(companyId, 'company');

      // Get all challenges created by this company
      const challengeAggregate = await Challenge.aggregate([
        {
          $match: {
            company: new Types.ObjectId(sanitizedCompanyId)
          }
        },
        {
          $facet: {
            // Count challenges by status
            statusCounts: [
              {
                $group: {
                  _id: '$status',
                  count: { $sum: 1 }
                }
              }
            ],
            // Top challenges by submission count
            topChallenges: [
              {
                $lookup: {
                  from: 'solutions',
                  localField: '_id',
                  foreignField: 'challenge',
                  as: 'solutions'
                }
              },
              {
                $project: {
                  id: '$_id',
                  title: '$title',
                  submissionCount: { $size: '$solutions' }
                }
              },
              {
                $sort: { submissionCount: -1 }
              },
              {
                $limit: 5
              }
            ]
          }
        }
      ]);

      // Process challenge counts by status
      const statusCounts = challengeAggregate[0].statusCounts.reduce((acc: Record<string, number>, curr: any) => {
        acc[curr._id] = curr.count;
        return acc;
      }, {});

      // Get solution statistics for this company's challenges
      const solutionStats = await Solution.aggregate([
        {
          $lookup: {
            from: 'challenges',
            localField: 'challenge',
            foreignField: '_id',
            as: 'challengeDetails'
          }
        },
        {
          $match: {
            'challengeDetails.company': new Types.ObjectId(sanitizedCompanyId)
          }
        },
        {
          $facet: {
            // Overall counts
            overall: [
              {
                $count: 'total'
              }
            ],
            // Counts by status
            statusCounts: [
              {
                $group: {
                  _id: '$status',
                  count: { $sum: 1 }
                }
              }
            ],
            // Count by challenge
            byChallenge: [
              {
                $group: {
                  _id: '$challenge',
                  count: { $sum: 1 }
                }
              }
            ]
          }
        }
      ]);

      const totalChallenges = Object.values(statusCounts).reduce((sum: number, count) => sum + (count as number), 0);
      const totalSubmissions = solutionStats[0].overall[0]?.total || 0;

      // Solution status counts
      const solutionStatusCounts = solutionStats[0].statusCounts.reduce((acc: Record<string, number>, curr: any) => {
        acc[curr._id] = curr.count;
        return acc;
      }, {});

      return {
        challenges: {
          total: totalChallenges,
          active: statusCounts[ChallengeStatus.ACTIVE] || 0,
          closed: statusCounts[ChallengeStatus.CLOSED] || 0,
          draft: statusCounts[ChallengeStatus.DRAFT] || 0
        },
        engagement: {
          totalSubmissions,
          averageSubmissionsPerChallenge: totalChallenges > 0 ? totalSubmissions / totalChallenges : 0,
          topChallenges: challengeAggregate[0].topChallenges || []
        },
        solutions: {
          selected: solutionStatusCounts[SolutionStatus.SELECTED] || 0,
          rejected: solutionStatusCounts[SolutionStatus.REJECTED] || 0,
          pending: (solutionStatusCounts[SolutionStatus.APPROVED] || 0)
        }
      };
    } catch (error) {
      logger.error(`Error getting company dashboard stats`, {
        companyId,
        error: error instanceof Error ? error.message : String(error)
      });

      if (error instanceof ApiError) throw error;

      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to retrieve company dashboard statistics',
        true,
        'DASHBOARD_STATS_ERROR'
      );
    }
  }
}

export const dashboardService = new DashboardService();