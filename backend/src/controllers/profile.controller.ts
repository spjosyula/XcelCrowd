import { Response, NextFunction } from 'express';
import { 
  profileService,
  CreateStudentProfileDTO, 
  UpdateStudentProfileDTO,
  CreateCompanyProfileDTO,
  UpdateCompanyProfileDTO,
  ProfileService
} from '../services/profile.service';
import { HTTP_STATUS } from '../constants';
import { catchAsync } from '../utils/catch.async';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { UserRole } from '../models/interfaces';
import { MongoSanitizer } from '../utils/mongo.sanitize';

/**
 * Profile controller for handling profile-related HTTP requests
 * Extends BaseController for standardized response handling
 * All business logic is delegated to the ProfileService
 */
export class ProfileController extends BaseController {
  private readonly profileService: ProfileService;
  constructor() {
    super();
    this.profileService = profileService;
  }

  /**
   * Create student profile
   * @route POST /api/profiles/student/:userId
   * @access Private - Student only (self)
   */
  public createStudentProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has student role
      this.verifyAuthorization(req, [UserRole.STUDENT]);
      const { userId } = req.params;
      
      // Authorization: ensure users can only create their own profile
      await this.profileService.authorizeSelfOperation(
        req.user!.userId, 
        userId, 
        'create-student-profile'
      );
      
      // Validate userId format using the centralized utility
      MongoSanitizer.validateObjectId(userId, 'user');
      
      // Prepare data and delegate to service
      const profileData: CreateStudentProfileDTO = {
        userId,
        ...req.body
      };
      
      const profile = await this.profileService.createStudentProfile(profileData);
      
      // Log action and send response
      this.logAction('student-profile-create', req.user!.userId);
      
      this.sendSuccess(
        res, 
        profile, 
        'Student profile created successfully', 
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Get student profile
   * @route GET /api/profiles/student/:userId
   * @access Private - Self or authorized roles
   */
  public getStudentProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);
      const { userId } = req.params;
      
      // Validate userId format using the centralized utility
      MongoSanitizer.validateObjectId(userId, 'user');
      
      // Authorization: check if user can access this profile
      await this.profileService.authorizeProfileReadAccess(
        req.user!.userId,
        req.user!.role as UserRole,
        userId,
        'student'
      );
      
      // Get profile via service
      const profile = await this.profileService.getStudentProfileByUserId(userId);
      
      // Log action and send response
      this.logAction('student-profile-view', req.user!.userId, { targetUserId: userId });
      
      this.sendSuccess(
        res, 
        profile, 
        'Student profile retrieved successfully'
      );
    }
  );

  /**
   * Update student profile
   * @route PUT /api/profiles/student/:userId
   * @access Private - Student only (self)
   */
  public updateStudentProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has student role
      this.verifyAuthorization(req, [UserRole.STUDENT]);
      const { userId } = req.params;
      
      // Authorization: ensure users can only update their own profile
      await this.profileService.authorizeSelfOperation(
        req.user!.userId, 
        userId, 
        'update-student-profile'
      );
      
      // Update profile via service
      const updateData: UpdateStudentProfileDTO = req.body;
      const profile = await this.profileService.updateStudentProfile(userId, updateData);
      
      // Log action and send response
      this.logAction('student-profile-update', req.user!.userId);
      
      this.sendSuccess(
        res, 
        profile, 
        'Student profile updated successfully'
      );
    }
  );

  /**
   * Create company profile
   * @route POST /api/profiles/company/:userId
   * @access Private - Company only (self)
   */
  public createCompanyProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has company role
      this.verifyAuthorization(req, [UserRole.COMPANY]);
      const { userId } = req.params;
      
      // Authorization: ensure users can only create their own profile
      await this.profileService.authorizeSelfOperation(
        req.user!.userId, 
        userId, 
        'create-company-profile'
      );
      
      // Prepare data and delegate to service
      const profileData: CreateCompanyProfileDTO = {
        userId,
        ...req.body
      };
      
      const profile = await this.profileService.createCompanyProfile(profileData);
      
      // Log action and send response
      this.logAction('company-profile-create', req.user!.userId);
      
      this.sendSuccess(
        res, 
        profile, 
        'Company profile created successfully', 
        HTTP_STATUS.CREATED
      );
    }
  );

  /**
   * Get company profile
   * @route GET /api/profiles/company/:userId
   * @access Private - Self or authorized roles
   */
  public getCompanyProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req);
      const { userId } = req.params;
      
      // Validate userId format using the centralized utility
      MongoSanitizer.validateObjectId(userId, 'user');
      
      // Authorization: check if user can access this profile
      await this.profileService.authorizeProfileReadAccess(
        req.user!.userId,
        req.user!.role as UserRole,
        userId,
        'company'
      );
      
      // Get profile via service
      const profile = await this.profileService.getCompanyProfileByUserId(userId);
      
      // Log action and send response
      this.logAction('company-profile-view', req.user!.userId, { targetUserId: userId });
      
      this.sendSuccess(
        res, 
        profile, 
        'Company profile retrieved successfully'
      );
    }
  );

  /**
   * Update company profile
   * @route PUT /api/profiles/company/:userId
   * @access Private - Company only (self)
   */
  public updateCompanyProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      // Verify user has company role
      this.verifyAuthorization(req, [UserRole.COMPANY]);
      const { userId } = req.params;
      
      // Authorization: ensure users can only update their own profile
      await this.profileService.authorizeSelfOperation(
        req.user!.userId, 
        userId, 
        'update-company-profile'
      );
      
      // Update profile via service
      const updateData: UpdateCompanyProfileDTO = req.body;
      const profile = await this.profileService.updateCompanyProfile(userId, updateData);
      
      // Log action and send response
      this.logAction('company-profile-update', req.user!.userId);
      
      this.sendSuccess(
        res, 
        profile, 
        'Company profile updated successfully'
      );
    }
  );
}

// Export singleton instance for use in routes
export const profileController = new ProfileController();