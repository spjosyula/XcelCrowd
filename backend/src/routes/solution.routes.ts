import { Router } from 'express';
import { solutionController } from '../controllers/solution.controller';
import { validateRequest } from '../middlewares/validation.middleware';
import { authenticate, authorizePattern, authorizeInstitutionForChallenge } from '../middlewares/auth.middleware';
import { AuthPattern } from '../types/authorization.types';
import { 
  submitSolutionSchema, 
  updateSolutionSchema,
  reviewSolutionSchema,
  selectSolutionAsWinnerSchema
} from '../validations/solution.validation';

const router = Router();

/**
 * @route   POST /api/solutions
 * @desc    Submit a solution to a challenge
 * @access  Private - Student only
 * @swagger
 * /solutions:
 */
router.post(
  '/',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  (req, res, next) => {
    if (req.body && req.body.challenge) {
      req.params.challengeId = req.body.challenge;
      return authorizeInstitutionForChallenge('challengeId')(req, res, next);
    }
    next();
  },
  validateRequest(submitSolutionSchema),
  solutionController.submitSolution
);

/**
 * @route   GET /api/solutions/student
 * @desc    Get all solutions submitted by current student
 * @access  Private - Student only
 * @swagger
 * /solutions/student:
 */
router.get(
  '/student',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  solutionController.getStudentSolutions
);

/**
 * @route   GET /api/solutions/architect
 * @desc    Get solutions reviewed by current architect
 * @access  Private - Architect only
 * @swagger
 * /solutions/architect:
 */
router.get(
  '/architect',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  solutionController.getArchitectReviews
);

/**
 * @route   GET /api/solutions/challenge/:challengeId
 * @desc    Get all solutions for a specific challenge
 * @access  Private - Company (owner) or Architect or Admin
 * @swagger
 * /solutions/challenge/{challengeId}:
 */
router.get(
  '/challenge/:challengeId',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_OR_ADMIN_OR_COMPANY),
  solutionController.getChallengeSolutions
);

/**
 * @route   GET /api/solutions/:id
 * @desc    Get solution by ID
 * @access  Private - Solution owner (Student) or Challenge owner (Company) or Architect or Admin
 * @swagger
 * /solutions/{id}:
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
 * @swagger
 * /solutions/{id}:
 */
router.put(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  validateRequest(updateSolutionSchema),
  solutionController.updateSolution
);

/**
 * @route   PATCH /api/solutions/:id/claim
 * @desc    Claim a solution for review
 * @access  Private - Architect only
 * @swagger
 * /solutions/{id}/claim:
 */
router.patch(
  '/:id/claim',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  solutionController.claimSolution
);

/**
 * @route   PATCH /api/solutions/:id/review
 * @desc    Review a solution (approve/reject with feedback)
 * @access  Private - Reviewing architect only
 * @swagger
 * /solutions/{id}/review:
 */
router.patch(
  '/:id/review',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  validateRequest(reviewSolutionSchema),
  solutionController.reviewSolution
);

/**
 * @route   PATCH /api/solutions/:id/select
 * @desc    Select a solution as a winner (by company)
 * @access  Private - Company (challenge owner) only
 * @swagger
 * /solutions/{id}/select:
 */
router.patch(
  '/:id/select',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  validateRequest(selectSolutionAsWinnerSchema),
  solutionController.selectSolution
);

export default router;