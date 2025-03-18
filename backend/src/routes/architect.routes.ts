import { Router } from 'express';
import { ArchitectController } from '../controllers/architect.controller';
import { authenticate } from '../middlewares/auth.middleware';
import { authorize } from '../middlewares/auth.middleware';
import { UserRole } from '../models/interfaces';

const router = Router();
const architectController = new ArchitectController();

/**
 * Architect routes
 * Base path: /api/architect
 */

// Middleware to ensure only architects can access these routes
const architectOnly = authorize([UserRole.ARCHITECT]);

// Profile routes
router.get(
  '/profile',
  authenticate,
  architectOnly,
  architectController.getProfile
);

router.put(
  '/profile',
  authenticate,
  architectOnly,
  architectController.updateProfile
);

// Dashboard route
router.get(
  '/dashboard',
  authenticate,
  architectOnly,
  architectController.getDashboardStats
);

// Solution routes
router.get(
  '/solutions',
  authenticate,
  architectOnly,
  architectController.getPendingSolutions
);

router.get(
  '/solutions/:id',
  authenticate,
  architectOnly,
  architectController.getSolution
);

router.post(
  '/solutions/:id/claim',
  authenticate,
  architectOnly,
  architectController.claimSolution
);

router.post(
  '/solutions/:id/review',
  authenticate,
  architectOnly,
  architectController.reviewSolution
);
router.post('/challenges/:challengeId/select-solutions', 
  authenticate, 
  architectOnly,
  architectController.selectSolutionsForCompany);

export default router; 