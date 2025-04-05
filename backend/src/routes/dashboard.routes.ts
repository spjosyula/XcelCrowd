import { Router } from 'express';
import { authenticate, authorizePattern } from '../middlewares/auth.middleware';
import { dashboardController } from '../controllers/dashboard.controller';
import { AuthPattern } from '../types/authorization.types';

const router = Router();

/**
 * @route   GET /api/dashboard/student
 * @desc    Get dashboard statistics for current student
 * @access  Private - Student only
 */
router.get(
  '/student',
  authenticate,
  authorizePattern(AuthPattern.STUDENT_ONLY),
  dashboardController.getStudentDashboard
);

/**
 * @route   GET /api/dashboard/company
 * @desc    Get dashboard statistics for current company
 * @access  Private - Company only
 */
router.get(
  '/company',
  authenticate,
  authorizePattern(AuthPattern.COMPANY_ONLY),
  dashboardController.getCompanyDashboard
);

/**
 * @route   GET /api/dashboard/architect
 * @desc    Retrieve statistics for architect's dashboard
 * @access  Private - Architect only
 */
router.get(
  '/architect',
  authenticate,
  authorizePattern(AuthPattern.ARCHITECT_ONLY),
  dashboardController.getArchitectDashboard
);

export default router;