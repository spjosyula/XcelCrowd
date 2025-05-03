import { z } from 'zod';

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
    }),
    
    // Email verification
    verifyEmail: z.object({
      email: z.string().email('Invalid email format'),
      otp: z.string().length(6, 'OTP must be 6 digits').regex(/^\d+$/, 'OTP must contain only digits')
    }),

    // Company email verification
    verifyCompanyEmail: z.object({
      email: z.string()
        .email('Invalid email format')
        .refine(
          (email) => {
            // Reject common personal email domains
            const personalDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com'];
            const domain = email.split('@')[1].toLowerCase();
            // This is a basic check - in production, consider using an email validation service
            return !personalDomains.includes(domain);
          },
          {
            message: 'Please use a business email address, not a personal email service'
          }
        ),
      otp: z.string()
        .length(6, 'Verification code must be 6 digits')
        .regex(/^\d+$/, 'Verification code must contain only digits')
    }),

    // Request password reset
    requestPasswordReset: z.object({
      email: z.string()
        .email('Invalid email format')
        .min(5, 'Email must be at least 5 characters')
        .max(100, 'Email cannot exceed 100 characters')
        .refine(
          (email) => {
            // Basic format validation beyond Zod's built-in email check
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
          },
          {
            message: 'Please enter a valid email address'
          }
        )
    }),

    // Reset password with token
    resetPassword: z.object({
      email: z.string()
        .email('Invalid email format')
        .min(5, 'Email must be at least 5 characters')
        .max(100, 'Email cannot exceed 100 characters'),
      otp: z.string()
        .length(6, 'Verification code must be 6 digits')
        .regex(/^\d+$/, 'Verification code must contain only digits'),
      newPassword: z.string()
        .min(8, 'Password must be at least 8 characters')
        .max(72, 'Password cannot exceed 72 characters') // bcrypt limit
        .regex(/^(?=.*[a-z])/, 'Password must contain at least one lowercase letter')
        .regex(/^(?=.*[A-Z])/, 'Password must contain at least one uppercase letter')
        .regex(/^(?=.*\d)/, 'Password must contain at least one number')
        .regex(/^(?=.*[!@#$%^&*(),.?":{}|<>])/, 'Password must contain at least one special character')
        .refine(
          (password) => {
            // Check for common passwords (abbreviated list - expand in production)
            const commonPasswords = ['Password123!', 'Admin123!', 'Welcome1!', 'Company1!'];
            return !commonPasswords.includes(password);
          },
          {
            message: 'Password is too common or easily guessable'
          }
        )
        .refine(
          (password) => {
            // Check for sequential patterns
            return !(/123|234|345|456|567|678|789|987|876|765|654|543|432|321/.test(password));
          },
          {
            message: 'Password contains sequential number patterns'
          }
        )
        .refine(
          (password) => {
            // Check for repeated characters (3 or more)
            return !(/(.)\1{2,}/.test(password));
          },
          {
            message: 'Password contains too many repeated characters'
          }
        )
    }).refine(
      (data) => {
        // Ensure password doesn't contain the email username
        const emailUsername = data.email.split('@')[0].toLowerCase();
        return !data.newPassword.toLowerCase().includes(emailUsername);
      },
      {
        message: 'Password should not contain parts of your email address',
        path: ['newPassword'] // Specify which field the error belongs to
      }
    )
};