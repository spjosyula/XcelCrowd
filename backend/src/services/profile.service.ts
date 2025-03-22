import { Types } from 'mongoose';
import { StudentProfile, CompanyProfile, IStudentProfile, ICompanyProfile, UserRole } from '../models';
import { ApiError } from '../utils/ApiError';
import { HTTP_STATUS } from '../constants';
import { UserService } from './user.service';
import mongoose from 'mongoose';
import { logger } from '../utils/logger';

export interface CreateStudentProfileDTO {
    userId: string;
    firstName?: string;
    lastName?: string;
    university?: string;
    resumeUrl?: string;
    bio?: string;
    profilePicture?: string;
    skills?: string[];
    interests?: string[];
}

export interface UpdateStudentProfileDTO extends Omit<CreateStudentProfileDTO, 'userId'> { }

export interface CreateCompanyProfileDTO {
    userId: string;
    companyName?: string;
    website?: string;
    contactNumber?: string;
    industry?: string;
    description?: string;
    address?: string;
}

export interface UpdateCompanyProfileDTO extends Omit<CreateCompanyProfileDTO, 'userId'> { }

/**
 * Profile service for handling profile-related operations
 */
export class ProfileService {
    private userService: UserService;

    constructor() {
        this.userService = new UserService();
    }

    /**
 * Create student profile with transaction support
 */
    public async createStudentProfile(profileData: CreateStudentProfileDTO): Promise<IStudentProfile> {
        // Start a MongoDB session for transaction support
        const session = await mongoose.startSession();

        try {
            session.startTransaction();

            // Validate user exists and has correct role
            const user = await this.userService.getUserById(profileData.userId);
            if (user.role !== UserRole.STUDENT) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User is not a student');
            }

            // Check if profile already exists
            const existingProfile = await StudentProfile.findOne({ user: profileData.userId }).session(session);
            if (existingProfile) {
                throw new ApiError(HTTP_STATUS.CONFLICT, 'Student profile already exists');
            }

            // Create profile with session for transaction
            const profile = await StudentProfile.create([{
                user: profileData.userId,
                firstName: profileData.firstName,
                lastName: profileData.lastName,
                university: profileData.university,
                resumeUrl: profileData.resumeUrl,
                bio: profileData.bio,
                profilePicture: profileData.profilePicture,
                skills: profileData.skills || [],
                interests: profileData.interests || [],
                followers: [],
                following: []
            }], { session });

            // Commit the transaction
            await session.commitTransaction();

            // Note: MongoDB's create returns an array when passed options with session
            return profile[0];
        } catch (error) {
            // Abort transaction on error
            await session.abortTransaction();

            logger.error(
                `Error creating student profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId: profileData.userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create student profile');
        } finally {
            // Always end the session
            session.endSession();
        }
    }

    /**
   * Delete student profile
   */
    public async deleteStudentProfile(userId: string): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const result = await StudentProfile.findOneAndDelete({ user: userId });
            if (!result) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete student profile');
        }
    }

    /**
     * Get student profile by user ID
     */
    public async getStudentProfileByUserId(userId: string): Promise<IStudentProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const profile = await StudentProfile.findOne({ user: userId }).populate('user', '-password');
            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }

            return profile;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve student profile');
        }
    }

    /**
     * Update student profile
     */
    public async updateStudentProfile(
        userId: string,
        updateData: UpdateStudentProfileDTO
    ): Promise<IStudentProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const profile = await StudentProfile.findOneAndUpdate(
                { user: userId },
                updateData,
                { new: true, runValidators: true }
            );

            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }

            return profile;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update student profile');
        }
    }

    /**
     * Create company profile
     */
    public async createCompanyProfile(profileData: CreateCompanyProfileDTO): Promise<ICompanyProfile> {
        try {
            // Validate user exists and has correct role
            const user = await this.userService.getUserById(profileData.userId);
            if (user.role !== UserRole.COMPANY) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User is not a company');
            }

            // Check if profile already exists
            const existingProfile = await CompanyProfile.findOne({ user: profileData.userId });
            if (existingProfile) {
                throw new ApiError(HTTP_STATUS.CONFLICT, 'Company profile already exists');
            }

            // Create profile
            const profile = await CompanyProfile.create({
                user: profileData.userId,
                companyName: profileData.companyName,
                website: profileData.website,
                contactNumber: profileData.contactNumber,
                industry: profileData.industry,
                description: profileData.description,
                address: profileData.address
            });

            return profile;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create company profile');
        }
    }

    /**
     * Get company profile by user ID
     */
    public async getCompanyProfileByUserId(userId: string): Promise<ICompanyProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const profile = await CompanyProfile.findOne({ user: userId }).populate('user', '-password');
            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }

            return profile;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve company profile');
        }
    }

    /**
     * Update company profile
     */
    public async updateCompanyProfile(
        userId: string,
        updateData: UpdateCompanyProfileDTO
    ): Promise<ICompanyProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const profile = await CompanyProfile.findOneAndUpdate(
                { user: userId },
                updateData,
                { new: true, runValidators: true }
            );

            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }

            return profile;
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update company profile');
        }
    }
    /**
   * Delete company profile
   */
    public async deleteCompanyProfile(userId: string): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID');
            }

            const result = await CompanyProfile.findOneAndDelete({ user: userId });
            if (!result) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }
        } catch (error) {
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete company profile');
        }
    }
}