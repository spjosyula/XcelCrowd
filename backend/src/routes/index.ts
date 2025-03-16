import express from 'express';
import userRoutes from './user.routes';
import profileRoutes from './profile.routes';
import authRoutes from './auth.routes';  

const router = express.Router();

/**
 * Health check route
 */
router.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

/**
 * API routes
 */
router.use('/auth', authRoutes);  
router.use('/users', userRoutes);
router.use('/profiles', profileRoutes);

export default router;