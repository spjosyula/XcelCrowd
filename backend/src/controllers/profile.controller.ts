import { Request, Response, NextFunction } from 'express';
import { 
  ProfileService, 
  CreateStudentProfileDTO, 
  UpdateStudentProfileDTO,
  CreateCompanyProfileDTO,
  UpdateCompanyProfileDTO
} from '../services/profile.service';
import { HTTP_STATUS } from '../constants';
import { ApiResponse } from '../utils/ApiResponse';
import { catchAsync } from '../utils/catchAsync';

/**
 * Profile controller for handling profile-related HTTP requests
 */
export class ProfileController {
  private profileService: ProfileService;

  constructor() {
    this.profileService = new ProfileService();
  }

  /**
   * Create student profile
   */
  public createStudentProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const profileData: CreateStudentProfileDTO = {
        userId: req.params.userId || req.body.userId,
        ...req.body
      };
      
      const profile = await this.profileService.createStudentProfile(profileData);
      
      res.status(HTTP_STATUS.CREATED).json(
        ApiResponse.success(profile, 'Student profile created successfully')
      );
    }
  );

  /**
   * Get student profile
   */
  public getStudentProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { userId } = req.params;
      const profile = await this.profileService.getStudentProfileByUserId(userId);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(profile, 'Student profile retrieved successfully')
      );
    }
  );

  /**
   * Update student profile
   */
  public updateStudentProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { userId } = req.params;
      const updateData: UpdateStudentProfileDTO = req.body;
      
      const profile = await this.profileService.updateStudentProfile(userId, updateData);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(profile, 'Student profile updated successfully')
      );
    }
  );

  /**
   * Create company profile
   */
  public createCompanyProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const profileData: CreateCompanyProfileDTO = {
        userId: req.params.userId || req.body.userId,
        ...req.body
      };
      
      const profile = await this.profileService.createCompanyProfile(profileData);
      
      res.status(HTTP_STATUS.CREATED).json(
        ApiResponse.success(profile, 'Company profile created successfully')
      );
    }
  );

  /**
   * Get company profile
   */
  public getCompanyProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { userId } = req.params;
      const profile = await this.profileService.getCompanyProfileByUserId(userId);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(profile, 'Company profile retrieved successfully')
      );
    }
  );

  /**
   * Update company profile
   */
  public updateCompanyProfile = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { userId } = req.params;
      const updateData: UpdateCompanyProfileDTO = req.body;
      
      const profile = await this.profileService.updateCompanyProfile(userId, updateData);
      
      res.status(HTTP_STATUS.OK).json(
        ApiResponse.success(profile, 'Company profile updated successfully')
      );
    }
  );
}