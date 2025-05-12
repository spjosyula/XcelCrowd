import { Router } from 'express';
import { aiEvaluationController } from '../controllers/ai-evaluation.controller';
import { validateRequest } from '../middlewares/validation.middleware';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { AuthPattern } from '../types/authorization.types';
import { startEvaluationSchema, getStatusSchema, retryEvaluationSchema } from '../validations/ai-evaluation.validation';

const router = Router();

/**
 * @route   POST /api/ai-evaluation/solutions/:solutionId/evaluate
 * @desc    Start AI evaluation for a solution
 * @access  Private - Admin, Architect, or Solution Owner only
 */
router.post(
  '/solutions/:solutionId/evaluate',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN_OR_COMPANY),
  validateRequest(startEvaluationSchema),
  aiEvaluationController.startEvaluation
);

/**
 * @route   GET /api/ai-evaluation/solutions/:solutionId/result
 * @desc    Get AI evaluation result for a solution
 * @access  Private - Admin, Architect, Company (Challenge Owner), or Solution Owner only
 */
router.get(
  '/solutions/:solutionId/result',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN_OR_COMPANY),
  aiEvaluationController.getEvaluationResult
);

/**
 * @route   GET /api/ai-evaluation/solutions/:solutionId/status
 * @desc    Check status of an ongoing evaluation
 * @access  Private - Admin, Architect, Company (Challenge Owner), or Solution Owner only
 */
router.get(
  '/solutions/:solutionId/status',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN_OR_COMPANY),
  validateRequest(getStatusSchema),
  aiEvaluationController.getEvaluationStatus
);

/**
 * @route   GET /api/ai-evaluation/analytics
 * @desc    Get analytics about AI evaluations (counts, success rates, etc.)
 * @access  Private - Admin only
 */
router.get(
  '/analytics',
  authenticate,
  authorizePattern(AuthPattern.ADMIN_ONLY),
  aiEvaluationController.getEvaluationAnalytics
);

/**
 * @route   POST /api/ai-evaluation/solutions/:solutionId/retry
 * @desc    Retry a failed evaluation
 * @access  Private - Admin or Architect only
 */
router.post(
  '/solutions/:solutionId/retry',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN),
  validateRequest(retryEvaluationSchema),
  aiEvaluationController.retryEvaluation
);

/**
 * @route   POST /api/ai-evaluation/challenges/:challengeId/process
 * @desc    Process all solutions for a challenge
 * @access  Private - Admin or Architect only
 */
router.post(
  '/challenges/:challengeId/process',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN),
  aiEvaluationController.processChallengeEvaluations
);

export default router;