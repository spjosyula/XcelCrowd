import express from 'express';
import { ProfileController } from '../controllers/profile.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { profileValidation } from '../validations/profile.validation';
import { UserRole } from '../models';

const router = express.Router();
const profileController = new ProfileController();

/**
 * Student profile routes
 */
router.post(
  '/student/:userId',
  authenticate,
  authorize([UserRole.STUDENT]), // Only students can create their profiles
  validateRequest(profileValidation.createStudentProfile),
  profileController.createStudentProfile
);

router.get(
  '/student/:userId',
  authenticate,
  profileController.getStudentProfile
);

router.put(
  '/student/:userId',
  authenticate,
  authorize([UserRole.STUDENT]), // Only students can update their profiles
  validateRequest(profileValidation.updateStudentProfile),
  profileController.updateStudentProfile
);

/**
 * Company profile routes
 */
router.post(
  '/company/:userId',
  authenticate,
  authorize([UserRole.COMPANY]), // Only companies can create their profiles
  validateRequest(profileValidation.createCompanyProfile),
  profileController.createCompanyProfile
);

router.get(
  '/company/:userId',
  authenticate,
  profileController.getCompanyProfile
);

router.put(
  '/company/:userId',
  authenticate,
  authorize([UserRole.COMPANY]), // Only companies can update their profiles
  validateRequest(profileValidation.updateCompanyProfile),
  profileController.updateCompanyProfile
);

export default router;