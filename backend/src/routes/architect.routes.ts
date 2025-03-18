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
 * All routes require authentication and architect role
 */

// Middleware to ensure only architects can access these routes
const architectOnly = authorize([UserRole.ARCHITECT]);

// Profile routes
router.get(
  '/profile',
  authenticate,
  architectOnly,
  architectController.getProfile
); // Gets architect's profile information

router.put(
  '/profile',
  authenticate,
  architectOnly,
  architectController.updateProfile
); // Updates architect's profile data

// Dashboard route
router.get(
  '/dashboard',
  authenticate,
  architectOnly,
  architectController.getDashboardStats
); // Retrieves statistics for architect's dashboard

// Solution routes
router.get(
  '/solutions',
  authenticate,
  architectOnly,
  architectController.getPendingSolutions
); // Gets list of solutions pending review

router.get(
  '/solutions/:id',
  authenticate,
  architectOnly,
  architectController.getSolution
); // Gets details of a specific solution

router.post(
  '/solutions/:id/claim', //Once the architect claims, no other architect can see it
  authenticate,
  architectOnly,
  architectController.claimSolution
); // Marks a solution as claimed by this architect 

router.post(
  '/solutions/:id/review',
  authenticate,
  architectOnly,
  architectController.reviewSolution
); // Submits architect's review of a solution

router.post('/challenges/:challengeId/select-solutions', 
  authenticate, 
  architectOnly,
  architectController.selectSolutionsForCompany
); // Selects winning solutions for a specific challenge

//In future, add /reviews/statistics route to get architect's review history

export default router;