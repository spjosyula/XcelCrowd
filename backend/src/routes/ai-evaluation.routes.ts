import { Router } from 'express';
import { aiEvaluationController } from '../controllers/ai-evaluation.controller';
import { validateRequest } from '../middlewares/validation.middleware';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { AuthPattern } from '../types/authorization.types';
import { startEvaluationSchema, getStatusSchema } from '../validations/ai-evaluation.validation';

const router = Router();

/**
 * @route   POST /api/ai-evaluation/solutions/:solutionId/evaluate
 * @desc    Start AI evaluation for a solution
 * @access  Private - Admin, Architect, or Solution Owner only
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/evaluate:
 *   post:
 *     summary: Start AI evaluation for a solution
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the solution to evaluate
 *     responses:
 *       200:
 *         description: Evaluation process started successfully
 *       400:
 *         description: Invalid input or solution in wrong state
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - user doesn't have required role
 *       404:
 *         description: Solution not found
 *       500:
 *         description: Server error
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
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/result:
 *   get:
 *     summary: Get AI evaluation result for a solution
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the solution to get evaluation for
 *     responses:
 *       200:
 *         description: Evaluation result retrieved successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - user doesn't have required role
 *       404:
 *         description: Evaluation not found
 *       500:
 *         description: Server error
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
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/status:
 *   get:
 *     summary: Check status of an in-progress evaluation
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the solution to check evaluation status
 *     responses:
 *       200:
 *         description: Evaluation status retrieved successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - user doesn't have required role
 *       404:
 *         description: No evaluation found for this solution
 *       500:
 *         description: Server error
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
 * @swagger
 * /ai-evaluation/analytics:
 *   get:
 *     summary: Get AI evaluation analytics
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Analytics data retrieved successfully
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - admin only
 *       500:
 *         description: Server error
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
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/retry:
 *   post:
 *     summary: Retry a failed evaluation
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the solution to retry evaluation
 *     responses:
 *       200:
 *         description: Evaluation retry initiated successfully
 *       400:
 *         description: Invalid request or evaluation not in failed state
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden - admin or architect only
 *       404:
 *         description: No evaluation found for this solution
 *       500:
 *         description: Server error
 */
router.post(
  '/solutions/:solutionId/retry',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN),
  aiEvaluationController.retryEvaluation
);

export default router;