import { z } from 'zod';
import { UserRole } from '../models';

/**
 * User validation schemas
 */
export const userValidation = {
  createUser: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(8, 'Password must be at least 8 characters')
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    role: z.enum([UserRole.STUDENT, UserRole.COMPANY, UserRole.ARCHITECT], {
      errorMap: () => ({ message: 'Invalid user role' })
    })
  }),
  
  updateUser: z.object({
    email: z.string().email('Invalid email format').optional(),
    password: z.string().min(8, 'Password must be at least 8 characters')
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
      .optional()
  })
};