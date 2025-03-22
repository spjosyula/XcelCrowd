import { Response, NextFunction } from 'express';
import { 
  ProfileService, 
  CreateStudentProfileDTO, 
  UpdateStudentProfileDTO,
  CreateCompanyProfileDTO,
  UpdateCompanyProfileDTO
} from '../services/profile.service';
import { HTTP_STATUS } from '../constants';
import { catchAsync } from '../utils/catchAsync';
import { BaseController } from './BaseController';
import { AuthRequest } from '../types/request.types';
import { ApiError } from '../utils/ApiError';
import { UserRole } from '../models/interfaces';

/**
 * Profile controller for handling profile-related HTTP requests
 * Extends BaseController for standardized response handling
 */
export class ProfileController extends BaseController {
  private profileService: ProfileService;

  constructor() {
    super();
    this.profileService = new ProfileService();
  }

  /**
   * Create student profile
   * @route POST /api/profiles/student/:userId
   * @access Private - Student only (self)
   */
  public createStudentProfile = catchAsync(
    async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
      this.verifyAuthorization(req, [UserRole.STUDENT]);
      const { userId } = req.params;
      
      // Ensure users can only create their own profile
      this.validateSelfOperation(req, userId);
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      const profileData: CreateStudentProfileDTO = {
        userId,
        ...req.body
      };
      
      const profile = await this.profileService.createStudentProfile(profileData);
      
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
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      // Allow the user to access their own profile, or company/admin/architect roles to access any profile
      const isSelfAccess = req.user!.userId === userId;
      const hasAccessRole = [UserRole.COMPANY, UserRole.ADMIN, UserRole.ARCHITECT]
                             .includes(req.user!.role as UserRole);
                             
      if (!isSelfAccess && !hasAccessRole) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to view this profile'
        );
      }
      
      const profile = await this.profileService.getStudentProfileByUserId(userId);
      
      if (!profile) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Student profile not found'
        );
      }
      
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
      this.verifyAuthorization(req, [UserRole.STUDENT]);
      const { userId } = req.params;
      
      // Ensure users can only update their own profile
      this.validateSelfOperation(req, userId);
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      const updateData: UpdateStudentProfileDTO = req.body;
      
      const profile = await this.profileService.updateStudentProfile(userId, updateData);
      
      if (!profile) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Student profile not found'
        );
      }
      
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
      this.verifyAuthorization(req, [UserRole.COMPANY]);
      const { userId } = req.params;
      
      // Ensure users can only create their own profile
      this.validateSelfOperation(req, userId);
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      const profileData: CreateCompanyProfileDTO = {
        userId,
        ...req.body
      };
      
      const profile = await this.profileService.createCompanyProfile(profileData);
      
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
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      // Allow the user to access their own profile, or admin/architect roles to access any profile
      const isSelfAccess = req.user!.userId === userId;
      const hasAccessRole = [UserRole.ADMIN, UserRole.ARCHITECT]
                             .includes(req.user!.role as UserRole);
                             
      if (!isSelfAccess && !hasAccessRole) {
        throw new ApiError(
          HTTP_STATUS.FORBIDDEN,
          'You do not have permission to view this profile'
        );
      }
      
      const profile = await this.profileService.getCompanyProfileByUserId(userId);
      
      if (!profile) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Company profile not found'
        );
      }
      
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
      this.verifyAuthorization(req, [UserRole.COMPANY]);
      const { userId } = req.params;
      
      // Ensure users can only update their own profile
      this.validateSelfOperation(req, userId);
      
      // Validate userId format
      this.validateObjectId(userId, 'user');
      
      const updateData: UpdateCompanyProfileDTO = req.body;
      
      const profile = await this.profileService.updateCompanyProfile(userId, updateData);
      
      if (!profile) {
        throw new ApiError(
          HTTP_STATUS.NOT_FOUND,
          'Company profile not found'
        );
      }
      
      this.logAction('company-profile-update', req.user!.userId);
      
      this.sendSuccess(
        res, 
        profile, 
        'Company profile updated successfully'
      );
    }
  );

  /**
   * Verify that the authenticated user is operating on their own data
   * @private
   */
  private validateSelfOperation(req: AuthRequest, targetUserId: string): void {
    if (req.user!.userId !== targetUserId) {
      throw new ApiError(
        HTTP_STATUS.FORBIDDEN,
        'You can only manage your own profile'
      );
    }
  }
}

// Export singleton instance for use in routes
export const profileController = new ProfileController();