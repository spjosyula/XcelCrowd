import express from 'express';
import { solutionController } from '../controllers/solution.controller';
import { 
  validateSubmitSolution, 
  validateUpdateSolution,
  validateReviewSolution
} from '../validations/solution.validation';
import { authorize, authenticate, authorizeInstitutionForChallenge } from '../middlewares/auth.middleware';
import { UserRole } from '../models/interfaces';

const router = express.Router();

/**
 * @route   POST /api/solutions
 * @desc    Submit a solution to a challenge
 * @access  Private - Student only
 */
router.post(
  '/',
  authenticate,
  authorize([UserRole.STUDENT]),
  (req, res, next) => {
    if (req.body && req.body.challenge) {
      req.params.challengeId = req.body.challenge;
      return authorizeInstitutionForChallenge('challengeId')(req, res, next);
    }
    next();
  },
  validateSubmitSolution,
  solutionController.submitSolution
);

/**
 * @route   GET /api/solutions/student
 * @desc    Get all solutions submitted by current student
 * @access  Private - Student only
 */
router.get(
  '/student',
  authenticate,
  authorize([UserRole.STUDENT]),
  solutionController.getStudentSolutions
);

/**
 * @route   GET /api/solutions/architect
 * @desc    Get solutions reviewed by current architect
 * @access  Private - Architect only
 */
router.get(
  '/architect',
  authenticate,
  authorize([UserRole.ARCHITECT]),
  solutionController.getArchitectReviews
);

/**
 * @route   GET /api/solutions/challenge/:challengeId
 * @desc    Get all solutions for a specific challenge
 * @access  Private - Company (owner) or Architect or Admin
 */
router.get(
  '/challenge/:challengeId',
  authenticate,
  authorize([UserRole.COMPANY, UserRole.ARCHITECT, UserRole.ADMIN]),
  solutionController.getChallengeSolutions
);

/**
 * @route   GET /api/solutions/:id
 * @desc    Get solution by ID
 * @access  Private - Solution owner (Student) or Challenge owner (Company) or Architect or Admin
 */
router.get(
  '/:id',
  authenticate,
  solutionController.getSolutionById
);

/**
 * @route   PUT /api/solutions/:id
 * @desc    Update a solution (before deadline)
 * @access  Private - Solution owner (Student) only
 */
router.put(
  '/:id',
  authenticate,
  authorize([UserRole.STUDENT]),
  validateUpdateSolution,
  solutionController.updateSolution
);

/**
 * @route   PATCH /api/solutions/:id/claim
 * @desc    Claim a solution for review
 * @access  Private - Architect only
 */
router.patch(
  '/:id/claim',
  authenticate,
  authorize([UserRole.ARCHITECT]),
  solutionController.claimSolution
);

/**
 * @route   PATCH /api/solutions/:id/review
 * @desc    Review a solution (approve/reject with feedback)
 * @access  Private - Reviewing architect only
 */
router.patch(
  '/:id/review',
  authenticate,
  authorize([UserRole.ARCHITECT]),
  validateReviewSolution,
  solutionController.reviewSolution
);

/**
 * @route   PATCH /api/solutions/:id/select
 * @desc    Select a solution as a winner (by company)
 * @access  Private - Company (challenge owner) only
 */
router.patch(
  '/:id/select',
  authenticate,
  authorize([UserRole.COMPANY]),
  solutionController.selectSolution
);

export default router;