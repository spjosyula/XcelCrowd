import express from 'express';
import { profileController } from '../controllers/profile.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { profileValidation } from '../validations/profile.validation';
import { AuthPattern } from '../types/authorization.types';

const router = express.Router();

/**
 * @route   POST /api/profiles/student/:userId
 * @desc    Create student profile
 * @access  Private - Student only (self)
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
 */
router.put(
  '/company/:userId',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  validateRequest(profileValidation.updateCompanyProfile),
  profileController.updateCompanyProfile
);

// /**
//  * @route   DELETE /api/profiles/student/:userId
//  * @desc    Delete student profile
//  * @access  Private - Self or Admin
//  */
// router.delete(
//   '/student/:userId',
//   authenticate,
//   authorizePattern(AuthPattern.SELF_OR_ADMIN),
//   profileController.deleteStudentProfile
// );

// /**
//  * @route   DELETE /api/profiles/company/:userId
//  * @desc    Delete company profile
//  * @access  Private - Self or Admin
//  */
// router.delete(
//   '/company/:userId',
//   authenticate,
//   authorizePattern(AuthPattern.SELF_OR_ADMIN),
//   profileController.deleteCompanyProfile
// );

export default router;