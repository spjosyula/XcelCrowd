import { Types } from 'mongoose';
import { StudentProfile, CompanyProfile, IStudentProfile, ICompanyProfile, UserRole } from '../models';
import { ApiError } from '../utils/ApiError';
import { HTTP_STATUS } from '../constants';
import { UserService } from './user.service';
import mongoose from 'mongoose';
import { logger } from '../utils/logger';

// Create an instance of UserService
const userService = new UserService();

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
 * Contains business logic for profile management
 */
export class ProfileService {
    /**
     * Authorize a self-operation on profiles
     * Ensures the requesting user is operating on their own profile
     * 
     * @param requestUserId - ID of the authenticated user making the request
     * @param targetUserId - ID of the user whose profile is being accessed
     * @param action - Description of the action being performed (for logs)
     * @throws ApiError if the operation is not authorized
     */
    public async authorizeSelfOperation(
        requestUserId: string,
        targetUserId: string,
        action: string
    ): Promise<void> {
        try {
            // Validate both IDs
            if (!requestUserId || !targetUserId) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'User IDs are required');
            }

            if (!Types.ObjectId.isValid(targetUserId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid target user ID format');
            }

            // Verify self-operation
            if (requestUserId !== targetUserId) {
                throw new ApiError(
                    HTTP_STATUS.FORBIDDEN,
                    'You can only manage your own profile'
                );
            }

            logger.info(`User ${requestUserId} authorized for self-operation: ${action}`);
        } catch (error) {
            logger.error(`Self-operation authorization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Authorization check failed');
        }
    }

    /**
     * Authorize profile read access
     * Determines if the requesting user can view a specific profile
     * 
     * @param requestUserId - ID of the authenticated user
     * @param requestUserRole - Role of the authenticated user
     * @param targetUserId - ID of the user whose profile is being viewed
     * @param profileType - Type of profile ('student' or 'company')
     * @throws ApiError if the user is not authorized to view the profile
     */
    public async authorizeProfileReadAccess(
        requestUserId: string,
        requestUserRole: UserRole,
        targetUserId: string,
        profileType: 'student' | 'company'
    ): Promise<void> {
        try {
            // Validate IDs
            if (!Types.ObjectId.isValid(targetUserId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid target user ID format');
            }

            // Self access is always allowed
            const isSelfAccess = requestUserId === targetUserId;

            // Define role-based access patterns
            const allowedRoles: Record<string, UserRole[]> = {
                'student': [UserRole.COMPANY, UserRole.ADMIN, UserRole.ARCHITECT],
                'company': [UserRole.ADMIN, UserRole.ARCHITECT]
            };

            const hasRoleAccess = allowedRoles[profileType]?.includes(requestUserRole);

            // Check access
            if (!isSelfAccess && !hasRoleAccess) {
                throw new ApiError(
                    HTTP_STATUS.FORBIDDEN,
                    `You do not have permission to view this ${profileType} profile`
                );
            }

            logger.info(`User ${requestUserId} authorized to view ${profileType} profile of ${targetUserId}`);
        } catch (error) {
            logger.error(`Profile view authorization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Authorization check failed');
        }
    }

    /**
     * Validate user role for profile operations
     */
    public async validateUserRole(userId: string, expectedRole: UserRole): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const user = await userService.getUserById(userId);

            if (user.role !== expectedRole) {
                throw new ApiError(
                    HTTP_STATUS.BAD_REQUEST,
                    `User is not a ${expectedRole.toLowerCase()}`
                );
            }

            logger.info(`User ${userId} role validated as ${expectedRole}`);
        } catch (error) {
            logger.error(`User role validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'User role validation failed');
        }
    }

    /**
     * Check if a profile exists for a user
     * @param userId - ID of the user
     * @param profileType - Type of profile ('student' or 'company')
     * @returns Boolean indicating if profile exists
     */
    public async profileExists(userId: string, profileType: 'student' | 'company'): Promise<boolean> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            let exists = false;

            if (profileType === 'student') {
                exists = !!(await StudentProfile.exists({ user: userId }));
            } else if (profileType === 'company') {
                exists = !!(await CompanyProfile.exists({ user: userId }));
            }

            return exists;
        } catch (error) {
            logger.error(`Error checking if profile exists: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to check if profile exists');
        }
    }

    /**
     * Create student profile with transaction support
     * @param profileData - Student profile data
     * @returns Created student profile
     */
    public async createStudentProfile(profileData: CreateStudentProfileDTO): Promise<IStudentProfile> {
        // Start a MongoDB session for transaction support
        const session = await mongoose.startSession();

        try {
            session.startTransaction();

            // Validate user exists and has correct role
            await this.validateUserRole(profileData.userId, UserRole.STUDENT);

            // Check if profile already exists
            const profileExists = await this.profileExists(profileData.userId, 'student');
            if (profileExists) {
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

            logger.info(`Student profile created for user ${profileData.userId}`);

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
     * Get student profile by user ID
     * @param userId - ID of the user
     * @returns Student profile
     */
    public async getStudentProfileByUserId(userId: string): Promise<IStudentProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            // OPTIMIZED: Limited fields in populated user document
            const profile = await StudentProfile.findOne({ user: userId })
                .populate('user', 'email role createdAt')
                .lean(); // OPTIMIZED: Added lean() for better performance

            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }

            return profile;
        } catch (error) {
            logger.error(`Error fetching student profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve student profile');
        }
    }

    /**
     * Update student profile
     * @param userId - ID of the user
     * @param updateData - Profile update data
     * @returns Updated student profile
     */
    public async updateStudentProfile(
        userId: string,
        updateData: UpdateStudentProfileDTO
    ): Promise<IStudentProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const profile = await StudentProfile.findOneAndUpdate(
                { user: userId },
                updateData,
                { new: true, runValidators: true }
            );

            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }

            logger.info(`Student profile updated for user ${userId}`);

            return profile;
        } catch (error) {
            logger.error(`Error updating student profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update student profile');
        }
    }

    /**
     * Create company profile
     * @param profileData - Company profile data
     * @returns Created company profile
     */
    public async createCompanyProfile(profileData: CreateCompanyProfileDTO): Promise<ICompanyProfile> {
        // Start a MongoDB session for transaction support
        const session = await mongoose.startSession();

        try {
            session.startTransaction();

            // Validate user exists and has correct role
            await this.validateUserRole(profileData.userId, UserRole.COMPANY);

            // Check if profile already exists
            const profileExists = await this.profileExists(profileData.userId, 'company');
            if (profileExists) {
                throw new ApiError(HTTP_STATUS.CONFLICT, 'Company profile already exists');
            }

            // Create profile with session for transaction
            const profile = await CompanyProfile.create([{
                user: profileData.userId,
                companyName: profileData.companyName,
                website: profileData.website,
                contactNumber: profileData.contactNumber,
                industry: profileData.industry,
                description: profileData.description,
                address: profileData.address
            }], { session });

            // Commit the transaction
            await session.commitTransaction();

            logger.info(`Company profile created for user ${profileData.userId}`);

            // Return the created profile
            return profile[0];
        } catch (error) {
            // Abort transaction on error
            await session.abortTransaction();

            logger.error(
                `Error creating company profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId: profileData.userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create company profile');
        } finally {
            // Always end the session
            session.endSession();
        }
    }

    /**
     * Get company profile by user ID
     * @param userId - ID of the user
     * @returns Company profile
     */
    public async getCompanyProfileByUserId(userId: string): Promise<ICompanyProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const profile = await CompanyProfile.findOne({ user: userId })
            .populate('user', 'email role createdAt')
            .lean(); // OPTIMIZED: Added lean() for better performance
            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }

            return profile;
        } catch (error) {
            logger.error(`Error fetching company profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to retrieve company profile');
        }
    }

    /**
     * Update company profile
     * @param userId - ID of the user
     * @param updateData - Profile update data
     * @returns Updated company profile
     */
    public async updateCompanyProfile(
        userId: string,
        updateData: UpdateCompanyProfileDTO
    ): Promise<ICompanyProfile> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const profile = await CompanyProfile.findOneAndUpdate(
                { user: userId },
                updateData,
                { new: true, runValidators: true }
            );

            if (!profile) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }

            logger.info(`Company profile updated for user ${userId}`);

            return profile;
        } catch (error) {
            logger.error(`Error updating company profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to update company profile');
        }
    }

    /**
     * Delete student profile
     * @param userId - ID of the user
     */
    public async deleteStudentProfile(userId: string): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const result = await StudentProfile.findOneAndDelete({ user: userId });
            if (!result) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Student profile not found');
            }

            logger.info(`Student profile deleted for user ${userId}`);
        } catch (error) {
            logger.error(`Error deleting student profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete student profile');
        }
    }

    /**
     * Delete company profile
     * @param userId - ID of the user
     */
    public async deleteCompanyProfile(userId: string): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw new ApiError(HTTP_STATUS.BAD_REQUEST, 'Invalid user ID format');
            }

            const result = await CompanyProfile.findOneAndDelete({ user: userId });
            if (!result) {
                throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Company profile not found');
            }

            logger.info(`Company profile deleted for user ${userId}`);
        } catch (error) {
            logger.error(`Error deleting company profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete company profile');
        }
    }
}

// Create and export singleton instance
export const profileService = new ProfileService();