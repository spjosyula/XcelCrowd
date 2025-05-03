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
 * @route   POST /api/auth/student/verify-email
 * @desc    Verify student's email with OTP
 * @access  Public
 * @swagger
 * /auth/student/verify-email:
 */
router.post(
  '/student/verify-email',
  validateRequest(authValidation.verifyEmail),
  authController.verifyStudentEmail
);

/**
 * @route   POST /api/auth/student/request-password-reset
 * @desc    Request password reset for student accounts (university email)
 * @access  Public
 * @swagger
 * /auth/student/request-password-reset:
 */
router.post(
  '/student/request-password-reset',
  validateRequest(authValidation.requestPasswordReset),
  authController.requestStudentPasswordReset
);

/**
 * @route   POST /api/auth/student/reset-password
 * @desc    Reset student password with OTP
 * @access  Public
 * @swagger
 * /auth/student/reset-password:
 */
router.post(
  '/student/reset-password',
  validateRequest(authValidation.resetPassword),
  authController.resetStudentPassword
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
 * @route   POST /api/auth/company/verify-email
 * @desc    Verify company's business email with OTP
 * @access  Public
 * @swagger
 * /auth/company/verify-email:
 */
router.post(
  '/company/verify-email',
  validateRequest(authValidation.verifyCompanyEmail),
  authController.verifyCompanyEmail
);

/**
 * @route   POST /api/auth/company/request-password-reset
 * @desc    Request password reset for company accounts (business email)
 * @access  Public
 * @swagger
 * /auth/company/request-password-reset:
 */
router.post(
  '/company/request-password-reset',
  validateRequest(authValidation.requestPasswordReset),
  authController.requestCompanyPasswordReset
);

/**
 * @route   POST /api/auth/company/reset-password
 * @desc    Reset company password with OTP
 * @access  Public
 * @swagger
 * /auth/company/reset-password:
 */
router.post(
  '/company/reset-password',
  validateRequest(authValidation.resetPassword),
  authController.resetCompanyPassword
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