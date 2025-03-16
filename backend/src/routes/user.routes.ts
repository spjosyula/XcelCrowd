import express from 'express';
import { UserController } from '../controllers/user.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';
import { validateRequest } from '../middlewares/validation.middleware';
import { UserRole } from '../models';
import { userValidation } from '../validations/user.validation';

const router = express.Router();
const userController = new UserController();

/**
 * @route   POST /api/users
 * @desc    Create a new user (Admin only)
 * @access  Private
 */
router.post(
  '/',
  authenticate,
  authorize([UserRole.ADMIN]), // Only admins can create users directly
  validateRequest(userValidation.createUser),
  userController.createUser
);

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Private
 */
router.get(
  '/:id',
  authenticate,
  userController.getUserById
);

/**
 * @route   PUT /api/users/:id
 * @desc    Update user
 * @access  Private
 */
router.put(
  '/:id',
  authenticate,
  validateRequest(userValidation.updateUser),
  userController.updateUser
);

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete user (Admin only)
 * @access  Private
 */
router.delete(
  '/:id',
  authenticate,
  authorize([UserRole.ADMIN]), // Only admins can delete users
  userController.deleteUser
);

export default router;