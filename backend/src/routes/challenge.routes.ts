import { Router, Request, Response, NextFunction } from 'express';
import { challengeController } from '../controllers/challenge.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { createChallengeSchemaWithRefinements, updateChallengeSchema } from '../validations/challenge.validation';
import { AuthPattern } from '../types/authorization.types';
import { catchAsync } from '../utils/catch.async';
import { profileService } from '../services/profile.service';
import Challenge from '../models/Challenge';
import { Types } from 'mongoose';
import { AuthRequest } from '../types/request.types';
import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { UserRole } from '../models/interfaces';

const router = Router();

/**
 * @route   GET /api/challenges/diagnostic/list-owned
 * @desc    For debugging only - List all challenges owned by the authenticated company user
 * @access  Private - Companies only
 */
router.get(
  '/diagnostic/list-owned',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  challengeController.listOwnedChallenges
);

/**
 * @route   GET /api/challenges/:id
 * @desc    Get a challenge by ID
 * @access  Private - Authentication required with dynamic permission checks
 * @swagger
 * /challenges/{id}:
 */
router.get(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.AUTHENTICATED),
  challengeController.getChallengeById
);

/**
 * @route   POST /api/challenges
 * @desc    Create a new challenge
 * @access  Private - Company only
 * @swagger
 * /challenges:
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
 * @swagger
 * /challenges:
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
 * @swagger
 * /challenges/company:
 */
router.get(
  '/company',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  challengeController.getCompanyChallenges
);

/**
 * @route   PUT /api/challenges/:id
 * @desc    Update a challenge
 * @access  Private - Challenge owner (Company) or Admin only
 * @swagger
 * /challenges/{id}:
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
 * @swagger
 * /challenges/{id}:
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
 * @swagger
 * /challenges/{id}/close:
 */
router.patch(
  '/:id/close',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.closeChallenge
);

/**
 * @route   POST /api/challenges/:id/complete
 * @desc    Complete a challenge with final selection results
 * @access  Private - Challenge owner (Company) only
 * @swagger
 * /challenges/{id}/complete:
 */
router.post(
  '/:id/complete',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  challengeController.completeChallenge
);

/**
 * @route   GET /api/challenges/:id/statistics
 * @desc    Get challenge statistics
 * @access  Private - Challenge owner (Company) or Admin only
 * @swagger
 * /challenges/{id}/statistics:
 */
router.get(
  '/:id/statistics',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.getChallengeStatistics
);

/**
 * @route   PATCH /api/challenges/:id/publish
 * @desc    Publish a challenge
 * @access  Private - Challenge owner (Company) or Admin only
 * @swagger
 * /challenges/{id}/publish:
 */
router.patch(
  '/:id/publish',
  authenticate,
  authorizePattern(AuthPattern.RESOURCE_OWNER),
  challengeController.publishChallenge
);

/**
 * @route POST /api/challenges/:id/process-for-review
 * @desc Process all solutions for a challenge and submit to architect review
 * @access Private - Admin, Company
 */
router.post(
  '/:id/process-for-review',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_OR_ADMIN),
  challengeController.processChallengeForReview
);

/**
 * @route   GET /api/challenges/:id/ownership-check
 * @desc    Diagnostic route for checking challenge ownership - FOR DEBUGGING ONLY
 * @access  Private - Company/Admin
 */
router.get(
  '/:id/ownership-check',
  authenticate,
  challengeController.checkChallengeOwnership
);

export default router;