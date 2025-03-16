import { z } from 'zod';
import { UserRole } from '../models';

/**
 * Profile validation schemas
 */
export const profileValidation = {
    createStudentProfile: z.object({
      firstName: z.string().min(1, 'First name is required').max(50).optional(),
      lastName: z.string().min(1, 'Last name is required').max(50).optional(),
      university: z.string().max(100).optional(),
      resumeUrl: z.string().url('Invalid URL format').optional(),
      bio: z.string().max(500, 'Bio cannot exceed 500 characters').optional(),
      profilePicture: z.string().url('Invalid URL format').optional(),
      skills: z.array(z.string()).optional(),
      interests: z.array(z.string()).optional()
    }),
    
    updateStudentProfile: z.object({
      firstName: z.string().min(1, 'First name is required').max(50).optional(),
      lastName: z.string().min(1, 'Last name is required').max(50).optional(),
      university: z.string().max(100).optional(),
      resumeUrl: z.string().url('Invalid URL format').optional(),
      bio: z.string().max(500, 'Bio cannot exceed 500 characters').optional(),
      profilePicture: z.string().url('Invalid URL format').optional(),
      skills: z.array(z.string()).optional(),
      interests: z.array(z.string()).optional()
    }),
    
    createCompanyProfile: z.object({
      companyName: z.string().min(1, 'Company name is required').max(100).optional(),
      website: z.string().url('Invalid URL format').optional(),
      contactNumber: z.string().regex(/^\+?[0-9]{10,15}$/, 'Invalid phone number format').optional(),
      industry: z.string().max(50).optional(),
      description: z.string().max(1000, 'Description cannot exceed 1000 characters').optional(),
      address: z.string().max(200).optional()
    }),
    
    updateCompanyProfile: z.object({
      companyName: z.string().min(1, 'Company name is required').max(100).optional(),
      website: z.string().url('Invalid URL format').optional(),
      contactNumber: z.string().regex(/^\+?[0-9]{10,15}$/, 'Invalid phone number format').optional(),
      industry: z.string().max(50).optional(), 
      description: z.string().max(1000, 'Description cannot exceed 1000 characters').optional(),
      address: z.string().max(200).optional()
    })
  };