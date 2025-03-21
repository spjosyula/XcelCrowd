import express from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate, loginRateLimiter } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { authValidation } from '../validations/auth.validation';
import { UserRole } from '../models';

const router = express.Router();
const authController = new AuthController();

/**
 * @route   POST /api/auth/logout
 * @desc    Logout current user
 * @access  Private
 */
router.post(
  '/logout',
  authenticate,
  authController.logout
);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user information
 * @access  Private
 */
router.get(
  '/me',
  authenticate,
  authController.getCurrentUser
);

/**
 * @route   POST /api/auth/student/register
 * @desc    Register a new student account
 * @access  Public
 */
router.post(
  '/student/register',
  validateRequest(authValidation.registerStudent),
  authController.registerStudent
);

/**
 * @route   POST /api/auth/student/login
 * @desc    Authenticate student and get token
 * @access  Public
 */
router.post(
  '/student/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginStudent
);

/**
 * @route   POST /api/auth/company/register
 * @desc    Register a new company account
 * @access  Public
 */
router.post(
  '/company/register',
  validateRequest(authValidation.registerCompany),
  authController.registerCompany
);

/**
 * @route   POST /api/auth/company/login
 * @desc    Authenticate company and get token
 * @access  Public
 */
router.post(
  '/company/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginCompany
);

export default router;