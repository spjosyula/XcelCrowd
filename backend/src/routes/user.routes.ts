import express from 'express';
import { userController } from '../controllers/user.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { UserRole } from '../models';
import { userValidation } from '../validations/user.validation';

const router = express.Router();

/**
 * @route   GET /api/users
 * @desc    Get all users (with filtering and pagination)
 * @access  Private - Admin only
 */
router.get(
  '/',
  authenticate,
  authorize([UserRole.ADMIN]),
  userController.getAllUsers
);

/**
 * @route   POST /api/users
 * @desc    Create a new user (Admin only)
 * @access  Private - Admin only
 */
router.post(
  '/',
  authenticate,
  authorize([UserRole.ADMIN]),
  validateRequest(userValidation.createUser),
  userController.createUser
);

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Private - Self or Admin only
 */
router.get(
  '/:id',
  authenticate,
  userController.getUserById
);

/**
 * @route   PUT /api/users/:id
 * @desc    Update user
 * @access  Private - Self or Admin only
 */
router.put(
  '/:id',
  authenticate,
  validateRequest(userValidation.updateUser),
  userController.updateUser
);

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete user
 * @access  Private - Admin only
 */
router.delete(
  '/:id',
  authenticate,
  authorize([UserRole.ADMIN]),
  userController.deleteUser
);

export default router;