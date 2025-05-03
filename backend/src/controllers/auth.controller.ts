import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserService, UserDocument, userService } from '../services/user.service';
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/api.error';
import { catchAsync } from '../utils/catch.async';
import { logger } from '../utils/logger';
import crypto from 'crypto';
import { UserRole } from '../models';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { profileService, ProfileService } from '../services/profile.service';
import { architectService, ArchitectService } from '../services/architect.service';
import { emailVerificationService, EmailVerificationService } from '../services/email.service';
import { token } from 'morgan';

/**
 * Interface for JWT token payload
 */
interface AuthTokenPayload {
  userId: string;
  email: string;
  role: string;
  profile?: string;
}

/**
 * Controller for authentication operations
 * Extends BaseController for standardized response handling
 */
export class AuthController extends BaseController {
  private readonly userService: UserService;
  private readonly profileService: ProfileService;
  private readonly architectService: ArchitectService;
  private readonly emailVerificationService: EmailVerificationService;

  constructor() {
    super();
    this.userService = userService
    this.profileService = profileService
    this.architectService = architectService
    this.emailVerificationService = emailVerificationService
  }

  /**
 * Common login logic for all user types
 */
  private async processLogin(
    email: string,
    password: string,
    expectedRole: UserRole,
    actionName: string
  ): Promise<{
    user: Partial<UserDocument>;
    profile?: any;
    token: string;
    csrfToken: string;
  }> {
    // Get user with password
    const user = await this.userService.getUserByEmail(email);

    // Check role match
    if (user.role !== expectedRole) {
      logger.warn(`Role mismatch in ${actionName}: ${email}, actual role: ${user.role}`);
      throw ApiError.unauthorized(`Invalid credentials for ${actionName}`);
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.warn(`Failed login attempt for ${actionName}: ${email}`);
      throw ApiError.unauthorized('Invalid credentials');
    }

    // Get profile if needed
    let profile = null;
    if (expectedRole !== UserRole.ADMIN) {
      try {
        if (expectedRole === UserRole.STUDENT) {
          profile = await this.profileService.getStudentProfileByUserId(user._id!.toString());
        } else if (expectedRole === UserRole.COMPANY) {
          profile = await this.profileService.getCompanyProfileByUserId(user._id!.toString());
        } else if (expectedRole === UserRole.ARCHITECT) {
          profile = await this.architectService.getProfileByUserId(user._id!.toString());
        }
      } catch (error) {
        // Profile not found is not fatal
        logger.warn(`Profile not found for ${actionName}: ${email}`);
      }
    }

    // Create token payload
    const tokenPayload: AuthTokenPayload = {
      userId: user._id!.toString(),
      email: user.email,
      role: user.role
    };

    // Add profile ID to token if profile exists
    if (profile && profile._id) {
      tokenPayload.profile = profile._id.toString();
    }

    // Generate token
    const token = this.generateToken(tokenPayload);

    // Generate CSRF token
    const csrfToken = crypto.randomBytes(64).toString('hex');

    // Sanitize user data
    const sanitizedUser = {
      _id: user._id,
      email: user.email,
      role: user.role,
    };

    // Log action
    this.logAction(`${expectedRole.toLowerCase()}-login`, user._id!.toString(), {
      email: user.email,
      profileId: profile?._id?.toString()
    });

    return {
      user: sanitizedUser,
      profile,
      token,
      csrfToken
    };
  }

  /**
  * Student registration with university email verification
  * @route POST /api/auth/student/register
  * @access Public
  */
  public registerStudent = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const userData = {
        ...req.body,
        role: UserRole.STUDENT
      };

      // Check password strength
      this.validatePasswordStrength(userData.password);

      // Verify university email (in production this should be more robust)
      const isUniversityEmail = this.emailVerificationService.isUniversityEmail(userData.email);

      if (!isUniversityEmail) {
        logger.warn(`Non-university email registration attempt: ${userData.email}`);
        // For now, just log the warning but allow registration
        // In production, you might want to reject non-university emails
        // throw ApiError.badRequest('Please use a valid university email address');
      }

      // Create user and profile in a single operation
      const user = await this.userService.createUser(userData);

      // Generate email verification token
      const verificationOtp = user.generateEmailVerificationToken();
      await user.save();

      // Create the student profile
      const profileData = {
        userId: user._id!.toString(),
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        university: req.body.university,
        // Include any other profile fields from the request
      };

      // Create the student profile
      const profile = await this.profileService.createStudentProfile(profileData);

      // Generate JWT token
      const token = this.generateToken({
        userId: user._id!.toString(),
        email: user.email,
        role: user.role
      });

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, token);

      // Generate CSRF token
      const csrfToken = crypto.randomBytes(64).toString('hex');

      // Send verification email with OTP
      await this.emailVerificationService.sendVerificationEmail(
        user.email,
        verificationOtp,
        'student'
      );

      this.logAction('student-register', user._id!.toString(), {
        email: user.email,
        profileCreated: true,
        verificationSent: true,
        isUniversityEmail
      });

      this.sendSuccess(
        res,
        {
          user,
          profile,
          csrfToken,
          message: 'Please verify your email to activate your account',
          isUniversityEmail
        },
        'Student registered successfully with profile',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Verify student email
   * @route POST /api/auth/student/verify-email
   * @access Public
   */
  public verifyStudentEmail = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, otp } = req.body;

      // Find user by email
      const user = await this.userService.getUserByEmail(email);

      if (user.isEmailVerified) {
        return this.sendSuccess(res, {}, 'Email already verified', HTTP_STATUS.OK);
      }

      // Verify the OTP
      const isValid = user.verifyEmailToken(otp);
      if (!isValid) {
        throw ApiError.badRequest('Invalid or expired verification code');
      }

      // Mark email as verified
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationTokenExpires = undefined;
      await user.save();

      this.logAction('email-verified', user._id!.toString(), {
        email: user.email
      });

      this.sendSuccess(
        res,
        {},
        'Email verified successfully',
        HTTP_STATUS.OK
      );
    }
  );

  /**
* Student login
* @route POST /api/auth/student/login
* @access Public
*/
  public loginStudent = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, password } = req.body;

      const result = await this.processLogin(email, password, UserRole.STUDENT, 'student-login');

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, result.token);

      this.sendSuccess(
        res,
        {
          user: result.user,
          profile: result.profile,
          csrfToken: result.csrfToken,
          token: result.token
        },
        'Student login successful'
      );
    }
  );

  /**
  * Request password reset for student accounts
  * @route POST /api/auth/student/request-password-reset
  * @access Public
  */
  public requestStudentPasswordReset = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email } = req.body;

      // Find user by email
      const user = await this.userService.getUserByEmail(email);

      // Verify the user is a student
      if (user.role !== UserRole.STUDENT) {
        throw ApiError.badRequest('Invalid account type');
      }

      // Verify university email
      const isUniversityEmail = this.emailVerificationService.isUniversityEmail(email);

      if (!isUniversityEmail) {
        logger.warn(`Password reset requested for non-university email: ${email}`);
        // For now, log warning but allow the operation
        // In production, you may want to enforce this more strictly
      }

      // Generate password reset token
      const resetOtp = user.generatePasswordResetToken();
      await user.save();

      // Send password reset email with OTP
      await this.emailVerificationService.sendVerificationEmail(
        user.email,
        resetOtp,
        'password-reset'
      );

      this.logAction('student-password-reset-requested', user._id!.toString(), {
        email: user.email,
        isUniversityEmail
      });

      // Don't reveal if user exists or not for security
      this.sendSuccess(
        res,
        {},
        'If a user with that email exists, a password reset link has been sent',
        HTTP_STATUS.OK
      );
    }
  );

  /**
   * Reset student password with OTP
   * @route POST /api/auth/student/reset-password
   * @access Public
   */
  public resetStudentPassword = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, otp, newPassword } = req.body;

      // Validate password strength
      this.validatePasswordStrength(newPassword);

      // Find user by email
      const user = await this.userService.getUserByEmail(email);

      // Verify the user is a student
      if (user.role !== UserRole.STUDENT) {
        throw ApiError.badRequest('Invalid account type');
      }

      // Verify the OTP
      if (!user.verifyPasswordResetToken(otp)) {
        throw ApiError.badRequest('Invalid or expired reset code');
      }

      // Update password
      user.password = newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetTokenExpires = undefined;
      await user.save();

      this.logAction('student-password-reset-completed', user._id!.toString(), {
        email: user.email
      });

      this.sendSuccess(
        res,
        {},
        'Password has been reset successfully',
        HTTP_STATUS.OK
      );
    }
  );


  public registerCompany = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const userData = {
        ...req.body,
        role: UserRole.COMPANY
      };

      // Check password strength
      this.validatePasswordStrength(userData.password);

      // Verify business email
      const isBusinessEmail = this.emailVerificationService.isBusinessEmail(userData.email);

      if (!isBusinessEmail) {
        logger.warn(`Non-business email registration attempt: ${userData.email}`);
        // For now, just log the warning but allow registration
        // In production, you might want to reject personal emails
        // throw ApiError.badRequest('Please use a valid business email address');
      }

      // Create user
      const user = await this.userService.createUser(userData);

      // Generate email verification token
      const verificationOtp = user.generateEmailVerificationToken();
      await user.save();

      // Create the company profile
      const profileData = {
        userId: user._id!.toString(),
        companyName: req.body.companyName,
        website: req.body.website,
        contactNumber: req.body.contactNumber,
        industry: req.body.industry,
        description: req.body.description,
        address: req.body.address
        // Include any other profile fields from the request
      };

      // Create the company profile
      const profile = await this.profileService.createCompanyProfile(profileData);

      // Generate token
      const token = this.generateToken({
        userId: user._id!.toString(),
        email: user.email,
        role: user.role
      });

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, token);

      // Generate CSRF token
      const csrfToken = crypto.randomBytes(64).toString('hex');

      // Send verification email with OTP
      await this.emailVerificationService.sendVerificationEmail(
        user.email,
        verificationOtp,
        'company'
      );

      this.logAction('company-register', user._id!.toString(), {
        email: user.email,
        profileCreated: true,
        verificationSent: true,
        isBusinessEmail
      });

      this.sendSuccess(
        res,
        {
          user,
          profile,
          csrfToken,
          message: 'Please verify your email to activate your account',
          isBusinessEmail
        },
        'Company registered successfully with profile',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
  * Verify company email
  * @route POST /api/auth/company/verify-email
  * @access Public
  */
  public verifyCompanyEmail = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, otp } = req.body;

      // Find user by email
      const user = await this.userService.getUserByEmail(email);

      // Verify the user is a company
      if (user.role !== UserRole.COMPANY) {
        throw ApiError.badRequest('Invalid account type');
      }

      if (user.isEmailVerified) {
        return this.sendSuccess(res, {}, 'Email already verified', HTTP_STATUS.OK);
      }

      // Verify the OTP
      const isValid = user.verifyEmailToken(otp);
      if (!isValid) {
        throw ApiError.badRequest('Invalid or expired verification code');
      }

      // Mark email as verified
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationTokenExpires = undefined;
      await user.save();

      this.logAction('company-email-verified', user._id!.toString(), {
        email: user.email
      });

      this.sendSuccess(
        res,
        {},
        'Business email verified successfully',
        HTTP_STATUS.OK
      );
    }
  );



  /**
 * Company login
 * @route POST /api/auth/company/login
 * @access Public
 */
  public loginCompany = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, password } = req.body;

      const result = await this.processLogin(email, password, UserRole.COMPANY, 'company-login');

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, result.token);

      this.sendSuccess(
        res,
        {
          user: result.user,
          profile: result.profile,
          csrfToken: result.csrfToken,
          token: result.token
        },
        'Company login successful'
      );
    }
  );

  /**
   * Request password reset for company accounts
   * @route POST /api/auth/company/request-password-reset
   * @access Public
   */
  public requestCompanyPasswordReset = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email } = req.body;

      // Find user by email
      const user = await this.userService.getUserByEmail(email);
      
      // Verify the user is a company
      if (user.role !== UserRole.COMPANY) {
        throw ApiError.badRequest('Invalid account type');
      }

      // Verify business email
      const isBusinessEmail = this.emailVerificationService.isBusinessEmail(email);
      
      if (!isBusinessEmail) {
        logger.warn(`Password reset requested for non-business email: ${email}`);
        // For now, log warning but allow the operation
        // In production, you may want to enforce this more strictly
      }

      // Generate password reset token
      const resetOtp = user.generatePasswordResetToken();
      await user.save();

      // Send password reset email with OTP
      await this.emailVerificationService.sendVerificationEmail(
        user.email, 
        resetOtp, 
        'password-reset'
      );

      this.logAction('company-password-reset-requested', user._id!.toString(), {
        email: user.email,
        isBusinessEmail
      });

      // Don't reveal if user exists or not for security
      this.sendSuccess(
        res,
        {},
        'If a user with that email exists, a password reset link has been sent',
        HTTP_STATUS.OK
      );
    }
  );

  /**
   * Reset company password with OTP
   * @route POST /api/auth/company/reset-password
   * @access Public
   */
  public resetCompanyPassword = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, otp, newPassword } = req.body;

      // Validate password strength
      this.validatePasswordStrength(newPassword);

      // Find user by email
      const user = await this.userService.getUserByEmail(email);
      
      // Verify the user is a company
      if (user.role !== UserRole.COMPANY) {
        throw ApiError.badRequest('Invalid account type');
      }

      // Verify the OTP
      if (!user.verifyPasswordResetToken(otp)) {
        throw ApiError.badRequest('Invalid or expired reset code');
      }

      // Update password
      user.password = newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetTokenExpires = undefined;
      await user.save();

      this.logAction('company-password-reset-completed', user._id!.toString(), {
        email: user.email
      });

      this.sendSuccess(
        res,
        {},
        'Password has been reset successfully',
        HTTP_STATUS.OK
      );
    }
  );

  /**
  * Architect login
  * @route POST /api/auth/architect/login
  * @access Public
  */
  public loginArchitect = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, password } = req.body;

      const result = await this.processLogin(email, password, UserRole.ARCHITECT, 'architect-login');

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, result.token);

      this.sendSuccess(
        res,
        {
          user: result.user,
          profile: result.profile,
          csrfToken: result.csrfToken
        },
        'Architect login successful'
      );
    }
  );

  /**
  * Admin login
  * @route POST /api/auth/admin/login
  * @access Public
  */
  public loginAdmin = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const { email, password } = req.body;

      const result = await this.processLogin(email, password, UserRole.ADMIN, 'admin-login');

      // Set HTTP-only cookie with token
      this.setTokenCookie(res, result.token);

      this.sendSuccess(
        res,
        {
          user: result.user,
          csrfToken: result.csrfToken
        },
        'Admin login successful'
      );
    }
  );

  /**
   * User logout
   * @route POST /api/auth/logout
   * @access Private
   */
  public logout = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Clear the JWT cookie
      res.clearCookie('jwt', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });

      if (req.user) {
        this.logAction('logout', req.user.userId);
      }

      this.sendSuccess(
        res,
        null,
        'Logged out successfully'
      );
    }
  );

  /**
   * Get current user profile
   * @route GET /api/auth/me
   * @access Private
   */
  public getCurrentUser = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);

      const user = await this.userService.getUserById(req.user!.userId);

      this.logAction('get-profile', req.user!.userId);

      this.sendSuccess(
        res,
        user,
        'User profile retrieved successfully'
      );
    }
  );


  /**
   * Generate JWT token
   * @private
   */
  private generateToken(payload: AuthTokenPayload): string {
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      const error = 'JWT_SECRET is not defined in environment variables';
      logger.error(error);
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Authentication service configuration error',
        false,
        'CONFIG_ERROR'
      );
    }

    return jwt.sign(payload, jwtSecret, {
      expiresIn: process.env.JWT_EXPIRE || '30d',
      algorithm: 'HS256',
      jwtid: crypto.randomUUID()
    } as jwt.SignOptions);
  }

  /**
   * Set HTTP-only secure cookie with JWT token
   * @private
   */
  private setTokenCookie(res: Response, token: string): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'strict' as const
    };

    res.cookie('jwt', token, cookieOptions);
  }

  /**
   * Validate password strength
   * @private
   */
  private validatePasswordStrength(password: string): void {
    const errors = [];

    if (!password || typeof password !== 'string') {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Password must be provided',
        true,
        'VALIDATION_ERROR'
      );
    }

    // Length check
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (password.length > 128) {
      errors.push('Password exceeds maximum length of 128 characters');
    }

    // Character type checks
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[@$!%*?&#^()_+\-=\[\]{};':"\\|,.<>\/]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Common patterns/dictionary check
    const commonPatterns = ['password', '12345', 'qwerty', 'admin'];
    const lowerPassword = password.toLowerCase();

    if (commonPatterns.some(pattern => lowerPassword.includes(pattern))) {
      errors.push('Password contains a common pattern that is easily guessed');
    }

    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
      errors.push('Password contains too many repeated characters');
    }

    if (errors.length > 0) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        errors.join('. '),
        true,
        'PASSWORD_POLICY_VIOLATION'
      );
    }
  }
}

// Export singleton instance for use in routes
export const authController = new AuthController();