import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { authenticate, loginRateLimiter } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { authValidation } from '../validations/auth.validation';

const router = Router();

/**
 * @route   POST /api/auth/logout
 * @desc    Logout current user
 * @access  Private - Authenticated users
 * @swagger
 * /auth/logout:
 */
router.post(
  '/logout',
  authenticate,
  authController.logout
);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user information
 * @access  Private - Authenticated users
 * @swagger
 * /auth/me:
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
 * @swagger
 * /auth/student/register:
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
 * @swagger
 * /auth/student/login:
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
 * @swagger
 * /auth/company/register:
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
 * @swagger
 * /auth/company/login:
 */
router.post(
  '/company/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginCompany
);

/**
 * @route   POST /api/auth/architect/login
 * @desc    Authenticate architect and get token
 * @access  Public
 * @swagger
 * /auth/architect/login:
 */
router.post(
  '/architect/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginArchitect
);

/**
 * @route   POST /api/auth/admin/login
 * @desc    Authenticate admin and get token
 * @access  Public
 * @swagger
 * /auth/admin/login:
 */
router.post(
  '/admin/login',
  loginRateLimiter,
  validateRequest(authValidation.login),
  authController.loginAdmin
);

export default router;