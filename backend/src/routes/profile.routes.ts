import express from 'express';
import { profileController } from '../controllers/profile.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { profileValidation } from '../validations/profile.validation';
import { UserRole } from '../models';

const router = express.Router();

/**
 * @route   POST /api/profiles/student/:userId
 * @desc    Create student profile
 * @access  Private - Student only
 */
router.post(
  '/student/:userId',
  authenticate,
  authorize([UserRole.STUDENT]),
  validateRequest(profileValidation.createStudentProfile),
  profileController.createStudentProfile
);

/**
 * @route   GET /api/profiles/student/:userId
 * @desc    Get student profile
 * @access  Private
 */
router.get(
  '/student/:userId',
  authenticate,
  profileController.getStudentProfile
);

/**
 * @route   PUT /api/profiles/student/:userId
 * @desc    Update student profile
 * @access  Private - Student only
 */
router.put(
  '/student/:userId',
  authenticate,
  authorize([UserRole.STUDENT]),
  validateRequest(profileValidation.updateStudentProfile),
  profileController.updateStudentProfile
);

/**
 * @route   POST /api/profiles/company/:userId
 * @desc    Create company profile
 * @access  Private - Company only
 */
router.post(
  '/company/:userId',
  authenticate,
  authorize([UserRole.COMPANY]),
  validateRequest(profileValidation.createCompanyProfile),
  profileController.createCompanyProfile
);

/**
 * @route   GET /api/profiles/company/:userId
 * @desc    Get company profile
 * @access  Private
 */
router.get(
  '/company/:userId',
  authenticate,
  profileController.getCompanyProfile
);

/**
 * @route   PUT /api/profiles/company/:userId
 * @desc    Update company profile
 * @access  Private - Company only
 */
router.put(
  '/company/:userId',
  authenticate,
  authorize([UserRole.COMPANY]),
  validateRequest(profileValidation.updateCompanyProfile),
  profileController.updateCompanyProfile
);

export default router;