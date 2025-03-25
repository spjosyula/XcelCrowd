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
 * @access  Private - Architect only
 */
router.get(
  '/solutions',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getPendingSolutions
);

/**
 * @route   GET /api/architect/solutions/:id
 * @desc    Get details of a specific solution
 * @access  Private - Architect only
 */
router.get(
  '/solutions/:id',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  architectController.getSolution
);

/**
 * @route   POST /api/architect/solutions/:id/claim
 * @desc    Claim a solution for review (once claimed, no other architect can see it)
 * @access  Private - Architect only
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
 */
router.post(
  '/challenges/:challengeId/select-solutions', 
  authenticate, 
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  validateRequest(selectSolutionsSchema),
  architectController.selectSolutionsForCompany
);

export default router;