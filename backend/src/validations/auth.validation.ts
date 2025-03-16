import { z } from 'zod';
import { UserRole } from '../models';

/**
 * Authentication validation schemas
 */
export const authValidation = {
    login: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string().min(1, 'Password is required')
    }),
    
    // Base registration schema with common fields
    baseRegistration: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string().min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
          'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    }),
    
    // Student registration (no role needed as it's implied by endpoint)
    registerStudent: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string().min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
          'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    }),
    
    // Company registration (no role needed as it's implied by endpoint)
    registerCompany: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string().min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
          'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    })
  };