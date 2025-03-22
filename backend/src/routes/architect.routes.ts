import { Router } from 'express';
import { architectController } from '../controllers/architect.controller';
import { authenticate } from '../middlewares/auth.middleware';
import { authorize } from '../middlewares/auth.middleware';
import { UserRole } from '../models/interfaces';

const router = Router();

// Middleware to ensure only architects can access these routes
const architectOnly = authorize([UserRole.ARCHITECT]);

/**
 * @route   GET /api/architect/profile
 * @desc    Get architect's profile information
 * @access  Private - Architect only
 */
router.get(
  '/profile',
  authenticate,
  architectOnly,
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
  architectOnly,
  architectController.updateProfile
);

/**
 * @route   GET /api/architect/dashboard
 * @desc    Retrieve statistics for architect's dashboard
 * @access  Private - Architect only
 */
router.get(
  '/dashboard',
  authenticate,
  architectOnly,
  architectController.getDashboardStats
);

/**
 * @route   GET /api/architect/solutions
 * @desc    Get list of solutions pending review
 * @access  Private - Architect only
 */
router.get(
  '/solutions',
  authenticate,
  architectOnly,
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
  architectOnly,
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
  architectOnly,
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
  architectOnly,
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
  architectOnly,
  architectController.selectSolutionsForCompany
);

export default router;