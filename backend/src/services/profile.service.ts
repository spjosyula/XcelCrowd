import { Types } from 'mongoose';
import { StudentProfile, CompanyProfile, IStudentProfile, ICompanyProfile, UserRole, ArchitectProfile } from '../models';
import { ApiError } from '../utils/api.error';
import { UserService } from './user.service';
import { logger } from '../utils/logger';
import { BaseService } from './BaseService';
import { MongoSanitizer } from '../utils/mongo.sanitize';

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

            // Use MongoSanitizer for enhanced validation and security
            const sanitizedTargetUserId = MongoSanitizer.validateObjectId(
                targetUserId, 
                'user', 
                { errorStatus: 400, additionalContext: 'During authorization check' }
            );

            // Verify self-operation with sanitized comparison
            if (requestUserId !== sanitizedTargetUserId) {
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
            // Enhanced validation with MongoSanitizer
            const sanitizedTargetUserId = MongoSanitizer.validateObjectId(
                targetUserId, 
                'user', 
                { errorStatus: 400, additionalContext: 'During authorization check' }
            );

            // Self access is always allowed - use sanitized ID for comparison
            const isSelfAccess = requestUserId === sanitizedTargetUserId;

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

            logger.info(`User ${requestUserId} authorized to view ${profileType} profile of ${sanitizedTargetUserId}`);
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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'During role validation' }
            );

            const user = await userService.getUserById(sanitizedUserId);

            if (user.role !== expectedRole) {
                throw ApiError.badRequest(
                    `User is not a ${expectedRole.toLowerCase()}`,
                    'INVALID_ROLE'
                );
            }

            logger.info(`User ${sanitizedUserId} role validated as ${expectedRole}`);
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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When checking profile existence' }
            );

            // Convert to ObjectId after validation
            const userObjectId = new Types.ObjectId(sanitizedUserId);
            let count = 0;

            // Create secure queries using $eq operator to prevent injection
            const query = { user: MongoSanitizer.buildEqualityCondition(userObjectId) };

            if (profileType === 'student') {
                // More efficient count operation with only _id projection
                count = await StudentProfile.countDocuments(query).limit(1);
            } else if (profileType === 'company') {
                count = await CompanyProfile.countDocuments(query).limit(1);
            }

            return count > 0;
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
                
                // Sanitize user ID
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    profileData.userId,
                    'user',
                    { errorStatus: 400, additionalContext: 'When creating student profile' }
                );

                // Check if profile already exists
                const profileExists = await this.profileExists(sanitizedUserId, 'student');
                if (profileExists) {
                    throw ApiError.conflict('Student profile already exists', 'PROFILE_ALREADY_EXISTS');
                }

                // Sanitize profile data
                const sanitizedProfile = this.sanitizeStudentProfileData(profileData);

                // Create profile with session for transaction
                const profile = await StudentProfile.create([{
                    user: sanitizedUserId,
                    firstName: sanitizedProfile.firstName,
                    lastName: sanitizedProfile.lastName,
                    university: sanitizedProfile.university,
                    resumeUrl: sanitizedProfile.resumeUrl,
                    bio: sanitizedProfile.bio,
                    profilePicture: sanitizedProfile.profilePicture,
                    skills: sanitizedProfile.skills || [],
                    interests: sanitizedProfile.interests || [],
                    followers: [],
                    following: []
                }], { session });

                logger.info(`Student profile created for user ${sanitizedUserId}`);

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
     * Sanitize student profile data to prevent injection attacks
     * @param profileData - Raw student profile data
     * @returns Sanitized profile data
     */
    private sanitizeStudentProfileData(profileData: CreateStudentProfileDTO): CreateStudentProfileDTO {
        const sanitized: CreateStudentProfileDTO = {
            userId: profileData.userId // This gets sanitized separately
        };

        // Sanitize string fields
        if (profileData.firstName !== undefined) {
            sanitized.firstName = MongoSanitizer.sanitizeString(profileData.firstName, {
                fieldName: 'First name',
                maxLength: 100
            });
        }

        if (profileData.lastName !== undefined) {
            sanitized.lastName = MongoSanitizer.sanitizeString(profileData.lastName, {
                fieldName: 'Last name',
                maxLength: 100
            });
        }

        if (profileData.university !== undefined) {
            sanitized.university = MongoSanitizer.sanitizeString(profileData.university, {
                fieldName: 'University',
                maxLength: 200
            });
        }

        if (profileData.bio !== undefined) {
            sanitized.bio = MongoSanitizer.sanitizeString(profileData.bio, {
                fieldName: 'Bio',
                maxLength: 500,
                required: false
            });
        }

        // Sanitize URL fields
        if (profileData.resumeUrl !== undefined) {
            sanitized.resumeUrl = MongoSanitizer.sanitizeUrl(profileData.resumeUrl, {
                fieldName: 'Resume URL',
                required: false
            });
        }

        if (profileData.profilePicture !== undefined) {
            sanitized.profilePicture = MongoSanitizer.sanitizeUrl(profileData.profilePicture, {
                fieldName: 'Profile picture URL',
                required: false
            });
        }

        // Sanitize array fields
        if (profileData.skills && Array.isArray(profileData.skills)) {
            sanitized.skills = profileData.skills.map(skill => 
                MongoSanitizer.sanitizeString(skill, {
                    fieldName: 'Skill',
                    maxLength: 50
                })
            );
        }

        if (profileData.interests && Array.isArray(profileData.interests)) {
            sanitized.interests = profileData.interests.map(interest => 
                MongoSanitizer.sanitizeString(interest, {
                    fieldName: 'Interest',
                    maxLength: 50
                })
            );
        }

        return sanitized;
    }

    /**
     * Get student profile by user ID
     * @param userId - ID of the user
     * @returns Student profile
     */
    public async getStudentProfileByUserId(userId: string): Promise<IStudentProfile> {
        try {
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When fetching student profile' }
            );

            // Create secure query using $eq operator to prevent injection
            const query = { user: { $eq: sanitizedUserId } };

            const profile = await StudentProfile.findOne(query)
                .populate('user', 'email role createdAt')
                .lean();

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
                // Use MongoSanitizer for enhanced validation
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    userId, 
                    'user', 
                    { errorStatus: 400, additionalContext: 'When updating student profile' }
                );

                // Sanitize update data
                const sanitizedUpdateData = this.sanitizeStudentProfileData({ 
                    userId: sanitizedUserId, 
                    ...updateData 
                });
                
                // Remove userId from the update object
                const { userId: _, ...updateFields } = sanitizedUpdateData;

                // Create secure query and sanitized update operations
                const query = { user: { $eq: sanitizedUserId } };
                const sanitizedUpdate = MongoSanitizer.sanitizeUpdateOperations(
                    { $set: updateFields },
                    [
                        'firstName', 'lastName', 'university', 'resumeUrl',
                        'bio', 'profilePicture', 'skills', 'interests'
                    ]
                );

                const profile = await StudentProfile.findOneAndUpdate(
                    query,
                    sanitizedUpdate,
                    { new: true, runValidators: true, session }
                );

                if (!profile) {
                    throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Student profile updated for user ${sanitizedUserId}`);

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
     * Sanitize company profile data to prevent injection attacks
     * @param profileData - Raw company profile data
     * @returns Sanitized profile data
     */
    private sanitizeCompanyProfileData(profileData: CreateCompanyProfileDTO): CreateCompanyProfileDTO {
        const sanitized: CreateCompanyProfileDTO = {
            userId: profileData.userId // This gets sanitized separately
        };

        // Sanitize string fields
        if (profileData.companyName !== undefined) {
            sanitized.companyName = MongoSanitizer.sanitizeString(profileData.companyName, {
                fieldName: 'Company name',
                maxLength: 200
            });
        }

        // Sanitize URL fields
        if (profileData.website !== undefined) {
            sanitized.website = MongoSanitizer.sanitizeUrl(profileData.website, {
                fieldName: 'Website URL',
                required: false
            });
        }

        // Sanitize other fields
        if (profileData.contactNumber !== undefined) {
            sanitized.contactNumber = MongoSanitizer.sanitizeString(profileData.contactNumber, {
                fieldName: 'Contact number',
                maxLength: 20,
                required: false,
                pattern: /^[+\d\s()-]{5,20}$/,
                patternErrorMessage: 'Contact number must be a valid phone number format'
            });
        }

        if (profileData.industry !== undefined) {
            sanitized.industry = MongoSanitizer.sanitizeString(profileData.industry, {
                fieldName: 'Industry',
                maxLength: 100,
                required: false
            });
        }

        if (profileData.description !== undefined) {
            sanitized.description = MongoSanitizer.sanitizeString(profileData.description, {
                fieldName: 'Description',
                maxLength: 1000,
                required: false
            });
        }

        if (profileData.address !== undefined) {
            sanitized.address = MongoSanitizer.sanitizeString(profileData.address, {
                fieldName: 'Address',
                maxLength: 300,
                required: false
            });
        }

        return sanitized;
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
                
                // Sanitize user ID
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    profileData.userId,
                    'user',
                    { errorStatus: 400, additionalContext: 'When creating company profile' }
                );

                // Check if profile already exists
                const profileExists = await this.profileExists(sanitizedUserId, 'company');
                if (profileExists) {
                    throw ApiError.conflict('Company profile already exists', 'PROFILE_ALREADY_EXISTS');
                }

                // Sanitize profile data
                const sanitizedProfile = this.sanitizeCompanyProfileData(profileData);

                // Create profile with session for transaction
                const profile = await CompanyProfile.create([{
                    user: sanitizedUserId,
                    companyName: sanitizedProfile.companyName,
                    website: sanitizedProfile.website,
                    contactNumber: sanitizedProfile.contactNumber,
                    industry: sanitizedProfile.industry,
                    description: sanitizedProfile.description,
                    address: sanitizedProfile.address
                }], { session });

                logger.info(`Company profile created for user ${sanitizedUserId}`);

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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When fetching company profile' }
            );

            // Create secure query using $eq operator to prevent injection
            const query = { user: { $eq: sanitizedUserId } };

            const profile = await CompanyProfile.findOne(query)
                .populate('user', 'email role createdAt')
                .lean();

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
                // Use MongoSanitizer for enhanced validation
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    userId, 
                    'user', 
                    { errorStatus: 400, additionalContext: 'When updating company profile' }
                );

                // Sanitize update data
                const sanitizedUpdateData = this.sanitizeCompanyProfileData({ 
                    userId: sanitizedUserId, 
                    ...updateData 
                });
                
                // Remove userId from the update object
                const { userId: _, ...updateFields } = sanitizedUpdateData;

                // Create secure query and sanitized update operations
                const query = { user: { $eq: sanitizedUserId } };
                const sanitizedUpdate = MongoSanitizer.sanitizeUpdateOperations(
                    { $set: updateFields },
                    [
                        'companyName', 'website', 'contactNumber', 
                        'industry', 'description', 'address'
                    ]
                );

                const profile = await CompanyProfile.findOneAndUpdate(
                    query,
                    sanitizedUpdate,
                    { new: true, runValidators: true, session }
                );

                if (!profile) {
                    throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Company profile updated for user ${sanitizedUserId}`);

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
                // Use MongoSanitizer for enhanced validation
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    userId, 
                    'user', 
                    { errorStatus: 400, additionalContext: 'When deleting student profile' }
                );

                // Create secure query using $eq operator to prevent injection
                const query = { user: { $eq: sanitizedUserId } };

                const result = await StudentProfile.findOneAndDelete(
                    query,
                    { session }
                );

                if (!result) {
                    throw ApiError.notFound('Student profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Student profile deleted for user ${sanitizedUserId}`);
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
                // Use MongoSanitizer for enhanced validation
                const sanitizedUserId = MongoSanitizer.validateObjectId(
                    userId, 
                    'user', 
                    { errorStatus: 400, additionalContext: 'When deleting company profile' }
                );

                // Create secure query using $eq operator to prevent injection
                const query = { user: { $eq: sanitizedUserId } };

                const result = await CompanyProfile.findOneAndDelete(
                    query,
                    { session }
                );

                if (!result) {
                    throw ApiError.notFound('Company profile not found', 'PROFILE_NOT_FOUND');
                }

                logger.info(`Company profile deleted for user ${sanitizedUserId}`);
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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When getting student profile ID' }
            );

            // Create secure query using $eq operator to prevent injection
            const query = { user: { $eq: sanitizedUserId } };

            const profile = await StudentProfile.findOne(query, '_id').lean();

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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When getting company profile ID' }
            );

            // Create secure query using $eq operator to prevent injection
            const query = { user: { $eq: sanitizedUserId } };

            const profile = await CompanyProfile.findOne(query, '_id').lean();

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
            // Use MongoSanitizer for enhanced validation
            const sanitizedUserId = MongoSanitizer.validateObjectId(
                userId, 
                'user', 
                { errorStatus: 400, additionalContext: 'When getting architect profile ID' }
            );

            // Create secure query using $eq operator to prevent injection
            const query = { user: { $eq: sanitizedUserId } };

            const profile = await ArchitectProfile.findOne(query, '_id').lean();

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