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

  constructor() {
    super();
    this.userService = userService
    this.profileService = profileService
    this.architectService = architectService
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
  * Student registration
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

      // Create user and profile in a single operation
      const user = await this.userService.createUser(userData);

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

      this.logAction('student-register', user._id!.toString(), {
        email: user.email,
        profileCreated: true
      });

      this.sendSuccess(
        res,
        { user, profile, csrfToken },
        'Student registered successfully with profile',
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Company registration
   * @route POST /api/auth/company/register
   * @access Public
   */
  public registerCompany = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      const userData = {
        ...req.body,
        role: UserRole.COMPANY
      };

      // Check password strength
      this.validatePasswordStrength(userData.password);

      // Create user
      const user = await this.userService.createUser(userData);

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

      this.logAction('company-register', user._id!.toString(), {
        email: user.email,
        profileCreated: true
      });

      this.sendSuccess(
        res,
        { user, profile, csrfToken },
        'Company registered successfully with profile',
        HTTP_STATUS.CREATED
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
    if (!password || password.length < 8) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Password must be at least 8 characters',
        true,
        'VALIDATION_ERROR'
      );
    }

    // Check for at least: 1 uppercase, 1 lowercase, 1 number, 1 special character
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!regex.test(password)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        true,
        'VALIDATION_ERROR'
      );
    }
  }
}

// Export singleton instance for use in routes
export const authController = new AuthController();