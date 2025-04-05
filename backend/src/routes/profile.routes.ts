import { Router } from 'express';
import { profileController } from '../controllers/profile.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { profileValidation } from '../validations/profile.validation';
import { AuthPattern } from '../types/authorization.types';

const router = Router();

/**
 * @route   POST /api/profiles/student/:userId
 * @desc    Create student profile
 * @access  Private - Student only (self)
 * @swagger
 * /profiles/student/{userId}:
 */
router.post(
  '/student/:userId',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  validateRequest(profileValidation.createStudentProfile),
  profileController.createStudentProfile
);

/**
 * @route   GET /api/profiles/student/:userId
 * @desc    Get student profile
 * @access  Private - Self or Company, Architect, Admin
 * @swagger
 * /profiles/student/{userId}:
 */
router.get(
  '/student/:userId',
  authenticate,
  authorizePattern(AuthPattern.AUTHENTICATED),
  profileController.getStudentProfile
);

/**
 * @route   PUT /api/profiles/student/:userId
 * @desc    Update student profile
 * @access  Private - Student only (self)
 * @swagger
 * /profiles/student/{userId}:
 */
router.put(
  '/student/:userId',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  validateRequest(profileValidation.updateStudentProfile),
  profileController.updateStudentProfile
);

/**
 * @route   POST /api/profiles/company/:userId
 * @desc    Create company profile
 * @access  Private - Company only (self)
 * @swagger
 * /profiles/company/{userId}:
 */
router.post(
  '/company/:userId',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  validateRequest(profileValidation.createCompanyProfile),
  profileController.createCompanyProfile
);

/**
 * @route   GET /api/profiles/company/:userId
 * @desc    Get company profile
 * @access  Private - Self or Architect, Admin
 * @swagger
 * /profiles/company/{userId}:
 */
router.get(
  '/company/:userId',
  authenticate,
  authorizePattern(AuthPattern.AUTHENTICATED),
  profileController.getCompanyProfile
);

/**
 * @route   PUT /api/profiles/company/:userId
 * @desc    Update company profile
 * @access  Private - Company only (self)
 * @swagger
 * /profiles/company/{userId}:
 */
router.put(
  '/company/:userId',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  validateRequest(profileValidation.updateCompanyProfile),
  profileController.updateCompanyProfile
);

export default router;