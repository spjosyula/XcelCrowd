import { Router } from 'express';
import { userController } from '../controllers/user.controller';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { AuthPattern } from '../types/authorization.types';
import { userValidation } from '../validations/user.validation';
import { createArchitectSchema } from '../validations/architect.validation';
import { architectController } from '../controllers/architect.controller';

const router = Router();

/**
 * @route   GET /api/users
 * @desc    Get all users (with filtering and pagination)
 * @access  Private - Admin only
 * @swagger
 * /users:
 */
router.get(
  '/',
  authenticate,
  authorizePattern(AuthPattern.ADMIN_ONLY),
  userController.getAllUsers
);

/**
 * @route   POST /api/users
 * @desc    Create a new user (Admin only)
 * @access  Private - Admin only
 * @swagger
 * /users:
 */
router.post(
  '/',
  authenticate,
  authorizePattern(AuthPattern.ADMIN_ONLY),
  validateRequest(userValidation.createUser),
  userController.createUser
);

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Private - Self or Admin only
 * @swagger
 * /users:/{id}:
 */
router.get(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.SELF_OR_ADMIN),
  userController.getUserById
);

/**
 * @route   PUT /api/users/:id
 * @desc    Update user
 * @access  Private - Self or Admin only
 * @swagger
 * /users:/{id}:
 */
router.put(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.SELF_OR_ADMIN),
  validateRequest(userValidation.updateUser),
  userController.updateUser
);

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete user
 * @access  Private - Admin only
 * @swagger
 * /users:/{id}:
 */
router.delete(
  '/:id',
  authenticate,
  authorizePattern(AuthPattern.ADMIN_ONLY),
  userController.deleteUser
);

/**
 * @route   POST /api/users/architects
 * @desc    Create a new architect user
 * @access  Private - Admin only
 * @swagger
 * /users/architects:
 */
router.post(
  '/architects',
  authenticate,
  authorizePattern(AuthPattern.ADMIN_ONLY),
  validateRequest(createArchitectSchema),
  architectController.createArchitectUser
);

// /**
//  * @route   GET /api/admin/metrics
//  * @desc    Get platform metrics and stats
//  * @access  Private - Admin only
//  */
// router.get(
//   '/metrics',
//   authenticate,
//   authorizePattern(AuthPattern.ADMIN_ONLY),
//   adminController.getPlatformMetrics
// );

// /**
//  * @route   GET /api/admin/logs
//  * @desc    Get system logs
//  * @access  Private - Admin only
//  */
// router.get(
//   '/logs',
//   authenticate,
//   authorizePattern(AuthPattern.ADMIN_ONLY),
//   adminController.getSystemLogs
// );

export default router;