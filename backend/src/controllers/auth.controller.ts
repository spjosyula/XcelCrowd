import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserService, UserDocument } from '../services/user.service'; 
import { HTTP_STATUS } from '../constants';
import { ApiError } from '../utils/ApiError';
import { catchAsync } from '../utils/catchAsync';
import { logger } from '../utils/logger';
import crypto from 'crypto';
import { UserRole } from '../models';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';

/**
 * Interface for JWT token payload
 */
interface AuthTokenPayload {
  userId: string;
  email: string;
  role: string;
}

/**
 * Controller for authentication operations
 * Extends BaseController for standardized response handling
 */
export class AuthController extends BaseController {
  private userService: UserService;

  constructor() {
    super();
    this.userService = new UserService();
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
      
      // Get strongly typed user document
      const user = await this.userService.createUser(userData);
      
      const token = this.generateToken({
        userId: user._id!.toString(),
        email: user.email,
        role: user.role
      });
      
      // Set HTTP-only cookie with token
      this.setTokenCookie(res, token);
      
      // Generate CSRF token
      const csrfToken = crypto.randomBytes(64).toString('hex');
      
      this.logAction('student-register', user._id!.toString(), { email: user.email });
      
      this.sendSuccess(
        res, 
        { user, csrfToken },
        'Student registered successfully',
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
      
      const token = this.generateToken({
        userId: user._id!.toString(),
        email: user.email,
        role: user.role
      });
      
      // Set HTTP-only cookie with token
      this.setTokenCookie(res, token);
      
      // Generate CSRF token
      const csrfToken = crypto.randomBytes(64).toString('hex');
      
      this.logAction('company-register', user._id!.toString(), { email: user.email });
      
      this.sendSuccess(
        res, 
        { user, csrfToken },
        'Company registered successfully',
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
      
      // Get user with password
      const user = await this.userService.getUserByEmail(email);
      
      // Check if user is a student
      if (user.role !== UserRole.STUDENT) {
        logger.warn(`Role mismatch in student login: ${email}, actual role: ${user.role}`);
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials for student login');
      }
      
      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        logger.warn(`Failed login attempt for student email: ${email}`);
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials');
      }
      
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
      
      this.logAction('student-login', user._id!.toString(), { email: user.email });
      
      this.sendSuccess(
        res, 
        { user, csrfToken },
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
      
      // Get user with password
      const user = await this.userService.getUserByEmail(email);
      
      // Check if user is a company
      if (user.role !== UserRole.COMPANY) {
        logger.warn(`Role mismatch in company login: ${email}, actual role: ${user.role}`);
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials for company login');
      }
      
      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        logger.warn(`Failed login attempt for company email: ${email}`);
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials');
      }
      
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
      
      this.logAction('company-login', user._id!.toString(), { email: user.email });
      
      this.sendSuccess(
        res, 
        { user, csrfToken },
        'Company login successful'
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