import { Types } from 'mongoose';
import { StudentProfile, CompanyProfile, IStudentProfile, ICompanyProfile, UserRole, ArchitectProfile } from '../models';
import { ApiError } from '../utils/api.error';
import { UserService } from './user.service';
import { logger } from '../utils/logger';
import { BaseService } from './BaseService';

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
export class ProfileService extends BaseService {
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
                throw ApiError.badRequest('User IDs are required', 'MISSING_USER_IDS');
            }

            if (!Types.ObjectId.isValid(targetUserId)) {
                throw ApiError.badRequest('Invalid target user ID format', 'INVALID_USER_ID');
            }

            // Verify self-operation
            if (requestUserId !== targetUserId) {
                throw ApiError.forbidden(
                    'You can only manage your own profile',
                    'SELF_OPERATION_REQUIRED'
                );
            }

            logger.info(`User ${requestUserId} authorized for self-operation: ${action}`);
        } catch (error) {
            logger.error(`Self-operation authorization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Authorization check failed', 'AUTH_CHECK_ERROR');
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
                throw ApiError.badRequest('Invalid target user ID format', 'INVALID_USER_ID');
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
                throw ApiError.forbidden(
                    `You do not have permission to view this ${profileType} profile`,
                    'PROFILE_ACCESS_DENIED'
                );
            }

            logger.info(`User ${requestUserId} authorized to view ${profileType} profile of ${targetUserId}`);
        } catch (error) {
            logger.error(`Profile view authorization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Authorization check failed', 'AUTH_CHECK_ERROR');
        }
    }

    /**
     * Validate user role for profile operations
     */
    public async validateUserRole(userId: string, expectedRole: UserRole): Promise<void> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            const user = await userService.getUserById(userId);

            if (user.role !== expectedRole) {
                throw ApiError.badRequest(
                    `User is not a ${expectedRole.toLowerCase()}`,
                    'INVALID_ROLE'
                );
            }

            logger.info(`User ${userId} role validated as ${expectedRole}`);
        } catch (error) {
            logger.error(`User role validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('User role validation failed', 'ROLE_VALIDATION_ERROR');
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
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
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
            throw ApiError.internal('Failed to check if profile exists', 'PROFILE_CHECK_ERROR');
        }
    }

    /**
     * Create student profile with transaction support
     * @param profileData - Student profile data
     * @returns Created student profile
     */
    public async createStudentProfile(profileData: CreateStudentProfileDTO): Promise<IStudentProfile> {
        try {
            return await this.withTransaction(async (session) => {
                // Validate user exists and has correct role
                await this.validateUserRole(profileData.userId, UserRole.STUDENT);

                // Check if profile already exists
                const profileExists = await this.profileExists(profileData.userId, 'student');
                if (profileExists) {
                    throw ApiError.conflict('Student profile already exists', 'PROFILE_ALREADY_EXISTS');
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

                logger.info(`Student profile created for user ${profileData.userId}`);

                // Note: MongoDB's create returns an array when passed options with session
                return profile[0];
            });
        } catch (error) {
            logger.error(
                `Error creating student profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId: profileData.userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal(
                'Failed to create student profile',
                'STUDENT_PROFILE_CREATION_ERROR'
            );
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
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            // OPTIMIZED: Limited fields in populated user document
            const profile = await StudentProfile.findOne({ user: userId })
                .populate('user', 'email role createdAt')
                .lean(); // OPTIMIZED: Added lean() for better performance

            if (!profile) {
                throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
            }

            return profile;
        } catch (error) {
            logger.error(`Error fetching student profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to retrieve student profile', 'STUDENT_PROFILE_RETRIEVAL_ERROR');
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
            return await this.withTransaction(async (session) => {
                if (!Types.ObjectId.isValid(userId)) {
                    throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
                }

                const profile = await StudentProfile.findOneAndUpdate(
                    { user: userId },
                    updateData,
                    { new: true, runValidators: true, session }
                );

                if (!profile) {
                    throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Student profile updated for user ${userId}`);

                return profile;
            });
        } catch (error) {
            logger.error(
                `Error updating student profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId, updateFields: Object.keys(updateData).join(','), error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal(
                'Failed to update student profile',
                'STUDENT_PROFILE_UPDATE_ERROR'
            );
        }
    }

    /**
     * Create company profile
     * @param profileData - Company profile data
     * @returns Created company profile
     */
    public async createCompanyProfile(profileData: CreateCompanyProfileDTO): Promise<ICompanyProfile> {
        try {
            return await this.withTransaction(async (session) => {
                // Validate user exists and has correct role
                await this.validateUserRole(profileData.userId, UserRole.COMPANY);

                // Check if profile already exists
                const profileExists = await this.profileExists(profileData.userId, 'company');
                if (profileExists) {
                    throw ApiError.conflict('Company profile already exists', 'PROFILE_ALREADY_EXISTS');
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

                logger.info(`Company profile created for user ${profileData.userId}`);

                // Return the created profile
                return profile[0];
            });
        } catch (error) {
            logger.error(
                `Error creating company profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId: profileData.userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to create company profile', 'COMPANY_PROFILE_CREATION_ERROR');
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
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            const profile = await CompanyProfile.findOne({ user: userId })
                .populate('user', 'email role createdAt')
                .lean(); // OPTIMIZED: Added lean() for better performance
                
            if (!profile) {
                throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
            }

            return profile;
        } catch (error) {
            logger.error(`Error fetching company profile: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to retrieve company profile', 'COMPANY_PROFILE_RETRIEVAL_ERROR');
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
            return await this.withTransaction(async (session) => {
                if (!Types.ObjectId.isValid(userId)) {
                    throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
                }

                const profile = await CompanyProfile.findOneAndUpdate(
                    { user: userId },
                    updateData,
                    { new: true, runValidators: true, session }
                );

                if (!profile) {
                    throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Company profile updated for user ${userId}`);

                return profile;
            });
        } catch (error) {
            logger.error(
                `Error updating company profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId, updateFields: Object.keys(updateData).join(','), error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to update company profile', 'COMPANY_PROFILE_UPDATE_ERROR');
        }
    }

    /**
     * Delete student profile
     * @param userId - ID of the user
     */
    public async deleteStudentProfile(userId: string): Promise<void> {
        try {
            await this.withTransaction(async (session) => {
                if (!Types.ObjectId.isValid(userId)) {
                    throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
                }

                const result = await StudentProfile.findOneAndDelete(
                    { user: userId },
                    { session }
                );

                if (!result) {
                    throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Student profile deleted for user ${userId}`);
            });
        } catch (error) {
            logger.error(
                `Error deleting student profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal(
                'Failed to delete student profile',
                'STUDENT_PROFILE_DELETION_ERROR'
            );
        }
    }

    /**
     * Delete company profile
     * @param userId - ID of the user
     */
    public async deleteCompanyProfile(userId: string): Promise<void> {
        try {
            await this.withTransaction(async (session) => {
                if (!Types.ObjectId.isValid(userId)) {
                    throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
                }

                const result = await CompanyProfile.findOneAndDelete(
                    { user: userId },
                    { session }
                );
                
                if (!result) {
                    throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Company profile deleted for user ${userId}`);
            });
        } catch (error) {
            logger.error(
                `Error deleting company profile: ${error instanceof Error ? error.message : String(error)}`,
                { userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to delete company profile', 'COMPANY_PROFILE_DELETION_ERROR');
        }
    }

    /**
     * Get student profile ID by user ID
     * @param userId - ID of the user
     * @returns Student profile ID
     */
    public async getStudentProfileId(userId: string): Promise<string> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            const profile = await StudentProfile.findOne({ user: userId }, '_id').lean();

            if (!profile) {
                throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
            }

            return profile._id.toString();
        } catch (error) {
            logger.error(`Error fetching student profile ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to retrieve student profile ID', 'STUDENT_PROFILE_ID_RETRIEVAL_ERROR');
        }
    }

    /**
     * Get company profile ID by user ID
     * @param userId - ID of the user
     * @returns Company profile ID
     */
    public async getCompanyProfileId(userId: string): Promise<string> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            const profile = await CompanyProfile.findOne({ user: userId }, '_id').lean();

            if (!profile) {
                throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
            }

            return profile._id.toString();
        } catch (error) {
            logger.error(`Error fetching company profile ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (error instanceof ApiError) throw error;
            throw ApiError.internal('Failed to retrieve company profile ID', 'COMPANY_PROFILE_ID_RETRIEVAL_ERROR');
        }
    }

    /**
     * Get architect profile ID by user ID
     * @param userId - ID of the user
     * @returns Architect profile ID
     */
    public async getArchitectProfileId(userId: string): Promise<string> {
        try {
            if (!Types.ObjectId.isValid(userId)) {
                throw ApiError.badRequest('Invalid user ID format', 'INVALID_USER_ID');
            }

            const profile = await ArchitectProfile.findOne({ user: userId }, '_id').lean();

            if (!profile) {
                throw ApiError.notFound('Architect profile not found', 'PROFILE_NOT_FOUND');
            }

            return profile._id.toString();
        } catch (error) {
            logger.error(
                `Error fetching architect profile ID: ${error instanceof Error ? error.message : String(error)}`,
                { userId, error }
            );

            if (error instanceof ApiError) throw error;
            throw ApiError.internal(
                'Failed to retrieve architect profile ID',
                'ARCHITECT_PROFILE_RETRIEVAL_ERROR'
            );
        }
    }
}

// Create and export singleton instance
export const profileService = new ProfileService();