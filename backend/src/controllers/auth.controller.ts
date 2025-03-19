import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserService, UserDocument } from '../services/user.service'; 
import { HTTP_STATUS } from '../constants';
import { ApiResponse } from '../utils/ApiResponse';
import { ApiError } from '../utils/ApiError';
import { catchAsync } from '../utils/catchAsync';
import { logger } from '../utils/logger';
import crypto from 'crypto';
import { UserRole } from '../models';


interface AuthTokenPayload { //specifies structure of data used to generate JWT token
  userId: string;
  email: string;
  role: string;
}

export class AuthController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  /**
   * Student registration
   */
  public registerStudent = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
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
      
      res.status(HTTP_STATUS.CREATED).json(
        ApiResponse.success(
          { 
            user, 
            csrfToken 
          }, 
          'Student registered successfully'
        )
      );
    }
  );

  /**
   * Company registration
   */
  public registerCompany = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
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
      
      res.status(HTTP_STATUS.CREATED).json(
        ApiResponse.success(
          { 
            user, 
            csrfToken 
          }, 
          'Company registered successfully'
        )
      );
    }
  );

  /**
   * Student login
   */
  public loginStudent = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { email, password } = req.body;
      
      // Get user with password
      const user = await this.userService.getUserByEmail(email);
      
      // Check if user is a student
      if (user.role !== UserRole.STUDENT) {
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials for student login');
      }
      
      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        logger.warn(`Failed login attempt for email: ${email}`);
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
      
      logger.info(`Student logged in: ${user.email}`);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(
          { 
            user, 
            csrfToken 
          }, 
          'Student login successful'
        )
      );
    }
  );

  /**
   * Company login
   */
  public loginCompany = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { email, password } = req.body;
      
      // Get user with password
      const user = await this.userService.getUserByEmail(email);
      
      // Check if user is a company
      if (user.role !== UserRole.COMPANY) {
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Invalid credentials for company login');
      }
      
      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        logger.warn(`Failed login attempt for email: ${email}`);
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
      
      logger.info(`Company logged in: ${user.email}`);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(
          { 
            user, 
            csrfToken, 
          }, 
          'Company login successful'
        )
      );
    }
  );
  
  /**
   * User logout
   */
  public logout = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      // Clear the JWT cookie
      res.clearCookie('jwt', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(null, 'Logged out successfully')
      );
    }
  );
  
  /**
   * Get current user profile
   */
  public getCurrentUser = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      // User is already attached to request by auth middleware
      const userId = req.user?.userId;
      
      if (!userId) {
        throw new ApiError(HTTP_STATUS.UNAUTHORIZED, 'Not authenticated');
      }

      const user = await this.userService.getUserById(userId);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(user, 'User profile retrieved successfully')
      );
    }
  );

  
  /**
   * Generate JWT token
   */
  private generateToken(payload: AuthTokenPayload): string {
    const jwtSecret = process.env.JWT_SECRET as string;
    
    if (!jwtSecret) {
      logger.error('JWT_SECRET is not defined in environment variables');
      throw new ApiError(
        HTTP_STATUS.INTERNAL_SERVER_ERROR,
        'Authentication service configuration error'
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
   */
  private setTokenCookie(res: Response, token: string): void {
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: 'strict'
    });
  }
  
  /**
   * Validate password strength
   */
  private validatePasswordStrength(password: string): void {
    if (!password || password.length < 8) {
      throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Password must be at least 8 characters');
    }
    
    // Check for at least: 1 uppercase, 1 lowercase, 1 number, 1 special character
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!regex.test(password)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST, 
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
      );
    }
  }
}