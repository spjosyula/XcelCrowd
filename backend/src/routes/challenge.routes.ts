import express from 'express';
import { challengeController } from '../controllers/challenge.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { createChallengeSchemaWithRefinements, updateChallengeSchema } from '../validations/challenge.validation';
import { AuthPattern } from '../types/authorization.types';

const router = express.Router();

/**
 * @route   POST /api/challenges
 * @desc    Create a new challenge
 * @access  Private - Company only
 */
router.post(
  '/',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  validateRequest(createChallengeSchemaWithRefinements),
  challengeController.createChallenge
);

/**
 * @route   GET /api/challenges
 * @desc    Get all challenges with filters
 * @access  Private - Authentication required
 */
router.get(
  '/',
  authenticate,
  authorizePattern(AuthPattern.AUTHENTICATED),
  challengeController.getAllChallenges
);

/**
 * @route   GET /api/challenges/company
 * @desc    Get all challenges created by current company
 * @access  Private - Company only
 */
router.get(
  '/company',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  challengeController.getCompanyChallenges
);

/**
 * @route   GET /api/challenges/:id
 * @desc    Get a challenge by ID
 * @access  Private - Authentication required with dynamic permission checks
 */
router.get(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.AUTHENTICATED),
  challengeController.getChallengeById
);

/**
 * @route   PUT /api/challenges/:id
 * @desc    Update a challenge
 * @access  Private - Challenge owner (Company) or Admin only
 */
router.put(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  validateRequest(updateChallengeSchema),
  challengeController.updateChallenge
);

/**
 * @route   DELETE /api/challenges/:id
 * @desc    Delete a challenge
 * @access  Private - Challenge owner (Company) or Admin only
 */
router.delete(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.deleteChallenge
);

/**
 * @route   PATCH /api/challenges/:id/close
 * @desc    Close a challenge for submissions
 * @access  Private - Challenge owner (Company) or Admin only
 */
router.patch(
  '/:id/close',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.closeChallenge
);

/**
 * @route   PATCH /api/challenges/:id/complete
 * @desc    Complete a challenge (finalize after review process)
 * @access  Private - Challenge owner (Company) or Admin only
 */
router.patch(
  '/:id/complete',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.completeChallenge
);

// Add statistics route
router.get(
  '/:id/statistics',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.getChallengeStatistics
);

// // Add solutions route -> to be implemented in future
// router.get(
//   '/:id/solutions',
//   authenticate,
//   authorizePattern(AuthPattern.RESOURCE_OWNER),
//   challengeController.getChallengeSolutions
// );

export default router;