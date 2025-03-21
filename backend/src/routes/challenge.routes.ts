import express from 'express';
import {
  createChallenge,
  getAllChallenges,
  getChallengeById,
  updateChallenge,
  deleteChallenge,
  closeChallenge,
  completeChallenge,
  getCompanyChallenges
} from '../controllers/challenge.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validateCreateChallenge, validateUpdateChallenge } from '../validations/challenge.validation'
import { UserRole } from '../models/interfaces';

const router = express.Router();

/**
 * @route   POST /api/challenges
 * @desc    Create a new challenge
 * @access  Private - Company only
 */
router.post(
  '/',
  authenticate,
  authorize([UserRole.COMPANY]),
  validateCreateChallenge,
  createChallenge
);

/**
 * @route   GET /api/challenges
 * @desc    Get all challenges with filters
 * @access  Public
 */
router.get(
  '/',
  getAllChallenges
);

/**
 * @route   GET /api/challenges/company
 * @desc    Get all challenges created by current company
 * @access  Private - Company only
 */
router.get(
  '/company',
  authenticate,
  authorize([UserRole.COMPANY]),
  getCompanyChallenges
);

/**
 * @route   GET /api/challenges/:id
 * @desc    Get a challenge by ID
 * @access  Public (with visibility restrictions)
 */
router.get(
  '/:id',
  getChallengeById
);

/**
 * @route   PUT /api/challenges/:id
 * @desc    Update a challenge
 * @access  Private - Challenge owner (Company) only
 */
router.put(
  '/:id',
  authenticate,
  authorize([UserRole.COMPANY]),
  validateUpdateChallenge,
  updateChallenge
);

/**
 * @route   DELETE /api/challenges/:id
 * @desc    Delete a challenge
 * @access  Private - Challenge owner (Company) or Admin only
 */
router.delete(
  '/:id',
  authenticate,
  authorize([UserRole.COMPANY, UserRole.ADMIN]),
  deleteChallenge
);

/**
 * @route   PATCH /api/challenges/:id/close
 * @desc    Close a challenge for submissions
 * @access  Private - Challenge owner (Company) only
 */
router.patch(
  '/:id/close',
  authenticate,
  authorize([UserRole.COMPANY]),
  closeChallenge
);

/**
 * @route   PATCH /api/challenges/:id/complete
 * @desc    Complete a challenge (finalize after review process)
 * @access  Private - Challenge owner (Company) only
 */
router.patch(
  '/:id/complete',
  authenticate,
  authorize([UserRole.COMPANY]),
  completeChallenge
);

export default router;