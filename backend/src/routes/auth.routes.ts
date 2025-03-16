import express from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate, loginRateLimiter } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { authValidation } from '../validations/auth.validation';
import { UserRole } from '../models';

const router = express.Router();
const authController = new AuthController();

/**
 * Common auth routes
 */
router.post(
  '/logout',
  authenticate,
  authController.logout
);

router.get(
  '/me',
  authenticate,
  authController.getCurrentUser
);

/**
 * Student auth routes
 */
router.post(
  '/student/register',
  validateRequest(authValidation.registerStudent),
  authController.registerStudent
);

router.post(
  '/student/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginStudent
);

/**
 * Company auth routes
 */
router.post(
  '/company/register',
  validateRequest(authValidation.registerCompany),
  authController.registerCompany
);

router.post(
  '/company/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginCompany
);

export default router;