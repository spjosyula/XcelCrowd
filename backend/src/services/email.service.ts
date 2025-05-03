import { ApiError } from '../utils/api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from '../utils/logger';
import { BaseService } from './BaseService';

/**
 * Service for handling email verification logic
 */
export class EmailVerificationService extends BaseService {
  /**
   * List of recognized university email domains (to be expanded/moved to database)
   * @private
   */
  private readonly universityDomains: string[] = [
    'edu', 'ac.uk', 'edu.au', 'edu.in', 'uni-', 'university', 'college'
    // In production, use a comprehensive database of university domains
  ];

  /**
   * List of recognized business email domains to exclude (common personal email providers)
   * @private
   */
  private readonly nonBusinessDomains: string[] = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com'
    // In production, this list should be more comprehensive
  ];

  /**
   * Verify if email belongs to a university
   * @param email - The email to verify
   * @returns Boolean indicating if email is a university email
   */
  public isUniversityEmail(email: string): boolean {
    try {
      const domain = this.getEmailDomain(email);
      
      // Check against recognized university domains
      return this.universityDomains.some(uniDomain => 
        domain.includes(uniDomain) || domain.endsWith('.' + uniDomain)
      );
      
      // In production: make API call to email verification service
      // or maintain a comprehensive database of university domains
    } catch (error) {
      logger.error(`Error verifying university email: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  /**
   * Verify if email is a business email (not a common personal email)
   * @param email - The email to verify
   * @returns Boolean indicating if email is a business email
   */
  public isBusinessEmail(email: string): boolean {
    try {
      const domain = this.getEmailDomain(email);
      
      // Simple check: not in list of common personal email domains
      return !this.nonBusinessDomains.includes(domain);
      
      // In production: use email verification API or more sophisticated checks
      // such as company domain validation, MX record verification, etc.
    } catch (error) {
      logger.error(`Error verifying business email: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  /**
   * Get domain part from an email address
   * @private
   */
  private getEmailDomain(email: string): string {
    return email.split('@')[1].toLowerCase();
  }

  /**
   * In production: implement email sending logic 
   * This is a placeholder function to simulate sending verification emails
   * @param email - Recipient email address
   * @param otp - One-time password for verification
   * @param type - Type of verification (student/company/password-reset)
   */
  public async sendVerificationEmail(email: string, otp: string, type: 'student' | 'company' | 'password-reset'): Promise<void> {
    try {
      // In production: integrate with a real email service (SendGrid, AWS SES, etc.)
      logger.info(`[EMAIL PLACEHOLDER] Sending ${type} verification email to ${email} with OTP: ${otp}`);
      
      // Simulating delay like a real email service
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Log success of "sending"
      logger.info(`[EMAIL PLACEHOLDER] Successfully sent ${type} verification email to ${email}`);
    } catch (error) {
      logger.error(`Failed to send verification email: ${error instanceof Error ? error.message : String(error)}`, {
        email,
        type,
        error
      });
      
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Failed to send verification email',
        true,
        'EMAIL_SENDING_FAILED'
      );
    }
  }
}

// Create and export singleton instance
export const emailVerificationService = new EmailVerificationService();