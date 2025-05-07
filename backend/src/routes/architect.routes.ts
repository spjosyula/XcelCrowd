import { Router } from 'express';
import { architectController } from '../controllers/architect.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { AuthPattern } from '../types/authorization.types';
import { 
  architectProfileSchema, 
  reviewSolutionSchema,
  selectSolutionsSchema 
} from '../validations/architect.validation';

const router = Router();

/**
 * @route   GET /api/architect/profile
 * @desc    Get architect's profile information
 * @access  Private - Architect only
 * @swagger
 * /architect/profile:
 */
router.get(
  '/profile',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getProfile
);

/**
 * @route   PUT /api/architect/profile
 * @desc    Update architect's profile data
 * @access  Private - Architect only
 * @swagger
 * /architect/profile:
 */
router.put(
  '/profile',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  validateRequest(architectProfileSchema),
  architectController.updateProfile
);

/**
 * @route   GET /api/architect/solutions
 * @desc    Get list of solutions pending review
 * @deprecated Use /challenges instead
 * @access  Private - Architect only
 * @swagger
 * /architect/solutions:
 */
router.get(
  '/solutions',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getPendingSolutions
);

/**
 * @route   GET /api/architect/challenges/pending
 * @desc    Get list of challenges pending review
 * @access  Private - Architect only
 * @swagger
 * /architect/challenges:
 */
router.get(
  '/challenges',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getPendingChallenges
);

/**
 * @route   GET /api/architect/solutions/:id
 * @desc    Get details of a specific solution
 * @access  Private - Architect only
 * @swagger
 * /architect/solutions/{id}:
 */
router.get(
  '/solutions/:id',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getSolution
);

/**
 * @route   GET /api/architect/solutions/:id/analytics
 * @desc    Get detailed analytics for a solution including AI evaluation
 * @access  Private - Architect only
 * @swagger
 * /architect/solutions/{id}/analytics:
 */
router.get(
  '/solutions/:id/analytics',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getSolutionAnalytics
);

/**
 * @route   POST /api/architect/challenges/:challengeId/claim
 * @desc    Claim a challenge for review
 * @access  Private - Architect only
 * @swagger
 * /architect/challenges/{challengeId}/claim:
 */
router.post(
  '/challenges/:challengeId/claim',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.claimChallenge
);

/**
 * @route   GET /api/architect/challenges/claimed
 * @desc    Get all challenges claimed by the architect
 * @access  Private - Architect only
 * @swagger
 * /architect/challenges/claimed:
 */
router.get(
  '/challenges/claimed',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getClaimedChallenges
);

/**
 * @route   POST /api/architect/solutions/:id/claim
 * @deprecated Use /challenges/:challengeId/claim instead
 * @desc    Claim a solution for review (once claimed, no other architect can see it)
 * @access  Private - Architect only
 * @swagger
 * /architect/solutions/{id}/claim:
 */
router.post(
  '/solutions/:id/claim',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.claimSolution
);

/**
 * @route   POST /api/architect/solutions/:id/review
 * @desc    Submit architect's review of a solution
 * @access  Private - Architect only
 * @swagger
 * /architect/solutions/{id}/review:
 */
router.post(
  '/solutions/:id/review',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  validateRequest(reviewSolutionSchema),
  architectController.reviewSolution
);

/**
 * @route   POST /api/architect/challenges/:challengeId/select-solutions
 * @desc    Select winning solutions for a specific challenge
 * @access  Private - Architect only
 * @swagger
 * /architect/challenges/{challengeId}/select-solutions:
 */
router.post(
  '/challenges/:challengeId/select-solutions', 
  authenticate, 
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  validateRequest(selectSolutionsSchema),
  architectController.selectSolutionsForCompany
);

export default router;