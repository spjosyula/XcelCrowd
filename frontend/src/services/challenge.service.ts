import api from './api';
import { AxiosError } from 'axios';
import { Challenge, ChallengeFilters, PaginatedChallenges } from '@/types/challenge';

// MongoDB error pattern we need to detect
const MONGODB_VISIBILITY_ERROR = "Cast to Array failed for value";

export class ChallengeService {
  /**
   * Fetch all challenges with optional filters
   * Requires authentication (student or admin role)
   */
  static async getAllChallenges(filters?: ChallengeFilters): Promise<PaginatedChallenges> {
    try {
      // Build query parameters
      const params = new URLSearchParams();
      
      // Add pagination parameters
      if (filters) {
        if (filters.page && !isNaN(Number(filters.page))) {
          params.append('page', filters.page.toString());
        }
        if (filters.limit && !isNaN(Number(filters.limit))) {
          params.append('limit', filters.limit.toString());
        }
        
        // CRITICAL FIX: Include status parameter to properly filter completed challenges
        if (filters.status && filters.status !== 'all') {
          params.append('status', filters.status);
        }
        
        // Add additional filter parameters
        if (filters.difficulty) {
          params.append('difficulty', filters.difficulty);
        }
        
        if (filters.searchTerm && filters.searchTerm.trim()) {
          params.append('searchTerm', filters.searchTerm.trim());
        }
      }

      // Make API request with all necessary params
      const response = await api.get<PaginatedChallenges>(`/api/challenges?${params.toString()}`);
      
      // Validate response structure
      if (!response.data || typeof response.data !== 'object') {
        throw new Error('Invalid response format from server');
      }
      
      return response.data;
    } catch (error) {
      // Use type assertion to get better type safety
      const axiosError = error as AxiosError;
      
      // Construct a meaningful error message
      let errorMessage = 'Failed to fetch challenges';
      let isVisibilityError = false;
      
      if (axiosError.response) {
        const status = axiosError.response.status;
        const responseData = axiosError.response.data as any;
        
        // Check for the specific MongoDB casting error pattern
        if (responseData && 
            responseData.error && 
            typeof responseData.error === 'string' && 
            responseData.error.includes(MONGODB_VISIBILITY_ERROR)) {
          isVisibilityError = true;
          errorMessage = 'Database filter error detected. Using local data filtering instead.';
          
          console.warn('MongoDB visibility filter error detected, switching to client-side filtering');
          
          // Fallback to client-side filtering
          return this.getAllChallengesWithClientSideFiltering(filters);
        } else if (status === 500) {
          errorMessage = `Server error (${status}): An internal server error occurred. The team has been notified.`;
          
          // Log specific error information for debugging
          console.warn('Challenge API 500 error details:', {
            status,
            url: axiosError.config?.url,
            params: axiosError.config?.params,
            data: responseData
          });
        } else if (status === 401 || status === 403) {
          errorMessage = 'You do not have permission to access this resource.';
        } else {
          // Try to extract message from response if available
          if (responseData && responseData.message) {
            errorMessage += `: ${responseData.message}`;
          } else {
            errorMessage += ': Unexpected error occurred';
          }
        }
      } else if (axiosError.request) {
        errorMessage = 'Unable to reach the server. Please check your connection.';
      } else {
        errorMessage = axiosError.message || 'An unknown error occurred';
      }
      
      // Log the problem
      console.error('Challenge service error:', {
        message: errorMessage,
        isVisibilityError,
        originalError: axiosError
      });
      
      // Re-throw with a better message
      const enhancedError = new Error(errorMessage) as Error & { 
        isHandled?: boolean; 
        originalError?: any;
        isVisibilityError?: boolean;
      };
      enhancedError.isHandled = true;
      enhancedError.originalError = axiosError;
      enhancedError.isVisibilityError = isVisibilityError;
      throw enhancedError;
    }
  }

  /**
   * Alternative implementation that fetches ALL challenges and filters them client-side
   * Use this as a fallback when the normal endpoint fails with visibility casting errors
   */
  static async getAllChallengesWithClientSideFiltering(filters?: ChallengeFilters): Promise<PaginatedChallenges> {
    try {
      // Create basic pagination parameters
      const params = new URLSearchParams();
      params.append('limit', '100'); // Request larger batch size to better handle filtering
      
      // Add the status parameter to ensure we get completed challenges as well when needed
      if (filters?.status && filters.status !== 'all') {
        params.append('status', filters.status);
      }
      
      // Get challenges with minimum server-side filtering to ensure we get COMPLETED challenges
      const allChallengesResponse = await api.get<PaginatedChallenges>(`/api/challenges?${params.toString()}`);
      
      if (!allChallengesResponse.data || !Array.isArray(allChallengesResponse.data.data)) {
        throw new Error('Invalid response format');
      }
      
      // Get all challenges
      const allChallenges = allChallengesResponse.data.data;
      
      // Apply client-side filtering
      let filteredChallenges = allChallenges;
      
      if (filters) {
        // Apply status filter if not already handled by backend query
        if (filters.status && filters.status !== 'all' && !params.has('status')) {
          filteredChallenges = filteredChallenges.filter(challenge => challenge.status === filters.status);
        }
        
        // Apply difficulty filter
        if (filters.difficulty) {
          filteredChallenges = filteredChallenges.filter(challenge => challenge.difficulty === filters.difficulty);
        }
        
        // Apply search term filter
        if (filters.searchTerm && filters.searchTerm.trim()) {
          const searchTerm = filters.searchTerm.trim().toLowerCase();
          filteredChallenges = filteredChallenges.filter(challenge => 
            challenge.title.toLowerCase().includes(searchTerm) ||
            challenge.description.toLowerCase().includes(searchTerm) ||
            challenge.tags.some(tag => tag.toLowerCase().includes(searchTerm))
          );
        }
      }
      
      // Calculate pagination
      const page = filters?.page || 1;
      const limit = filters?.limit || 10;
      const total = filteredChallenges.length;
      
      // Apply pagination
      const startIndex = (page - 1) * limit;
      const endIndex = Math.min(startIndex + limit, total);
      const paginatedChallenges = filteredChallenges.slice(startIndex, endIndex);
      
      // Return paginated result
      return {
        data: paginatedChallenges,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: endIndex < total,
        hasPrevPage: page > 1
      };
    } catch (error) {
      console.error('Error in client-side challenge filtering:', error);
      throw error;
    }
  }

  /**
   * Fetch a single challenge by ID
   * Requires authentication (student or admin role)
   */
  static async getChallengeById(id: string): Promise<Challenge> {
    try {
      // Validate ID to prevent unnecessary API calls
      if (!id || typeof id !== 'string' || id.trim() === '') {
        throw new Error('Invalid challenge ID');
      }
      
      const response = await api.get<{ data: Challenge, message: string }>(`/api/challenges/${id}`);
      
      // Validate response structure
      if (!response.data || !response.data.data) {
        throw new Error('Invalid response format from server');
      }
      
      return response.data.data;
    } catch (error) {
      // Use type assertion to get better type safety
      const axiosError = error as AxiosError;
      
      // Construct a meaningful error message
      let errorMessage = `Failed to fetch challenge (ID: ${id})`;
      
      if (axiosError.response) {
        const status = axiosError.response.status;
        
        if (status === 404) {
          errorMessage = `Challenge not found (ID: ${id})`;
        } else if (status === 500) {
          errorMessage = 'Server error: An internal server error occurred. The team has been notified.';
        } else if (status === 401 || status === 403) {
          errorMessage = 'You do not have permission to access this challenge.';
        } else {
          // Try to extract message from response if available
          const data = axiosError.response.data as any;
          if (data && data.message) {
            errorMessage += `: ${data.message}`;
          }
        }
      } else if (axiosError.request) {
        errorMessage = 'Unable to reach the server. Please check your connection.';
      } else {
        errorMessage = axiosError.message || 'An unknown error occurred';
      }
      
      // Re-throw with a better message
      const enhancedError = new Error(errorMessage) as Error & { isHandled?: boolean; originalError?: any };
      enhancedError.isHandled = true;
      enhancedError.originalError = axiosError;
      throw enhancedError;
    }
  }

  /**
   * Create a new challenge
   * Requires authentication (company role)
   */
  static async createChallenge(challengeData: Partial<Challenge>): Promise<Challenge> {
    try {
      // Validate critical required fields to prevent unnecessary API calls
      if (!challengeData.title || !challengeData.description) {
        throw new Error('Challenge title and description are required');
      }
      
      // Use the RESTful endpoint for challenge creation (POST /challenges)
      const response = await api.post<{ data: Challenge, message: string }>('/api/challenges', challengeData);
      
      // Validate response structure
      if (!response.data || !response.data.data) {
        throw new Error('Invalid response format from server');
      }
      
      return response.data.data;
    } catch (error) {
      // Use type assertion to get better type safety
      const axiosError = error as AxiosError;
      
      // Construct a meaningful error message
      let errorMessage = 'Failed to create challenge';
      
      if (axiosError.response) {
        const status = axiosError.response.status;
        
        if (status === 400) {
          // Bad request - validation error
          const data = axiosError.response.data as any;
          errorMessage = data?.message || 'Challenge validation failed. Please check your inputs.';
        } else if (status === 500) {
          errorMessage = 'Server error: An internal server error occurred. The team has been notified.';
        } else if (status === 401 || status === 403) {
          errorMessage = 'You do not have permission to create challenges.';
        } else {
          // Try to extract message from response if available
          const data = axiosError.response.data as any;
          if (data && data.message) {
            errorMessage += `: ${data.message}`;
          }
        }
      } else if (axiosError.request) {
        errorMessage = 'Unable to reach the server. Please check your connection.';
      } else {
        errorMessage = axiosError.message || 'An unknown error occurred';
      }
      
      console.error('Challenge creation error:', {
        message: errorMessage,
        originalError: axiosError
      });
      
      // Re-throw with a better message
      const enhancedError = new Error(errorMessage) as Error & { isHandled?: boolean; originalError?: any };
      enhancedError.isHandled = true;
      enhancedError.originalError = axiosError;
      throw enhancedError;
    }
  }

  /**
   * Publish a challenge (transition from DRAFT to ACTIVE)
   * Requires authentication (company role)
   * @param id Challenge ID to publish
   */
  static async publishChallenge(id: string): Promise<Challenge> {
    try {
      // Validate ID
      if (!id || typeof id !== 'string' || id.trim() === '') {
        throw new Error('Invalid challenge ID');
      }
      
      console.log(`Attempting to publish challenge ${id}`);
      
      // Use the RESTful endpoint for challenge publication (PATCH /challenges/:id/publish)
      const response = await api.patch<{ data: Challenge, message: string }>(`/api/challenges/${id}/publish`);
      
      // Validate response structure
      if (!response.data || !response.data.data) {
        throw new Error('Invalid response format from server');
      }
      
      console.log(`Challenge ${id} published successfully with status: ${response.data.data.status}`);
      return response.data.data;
    } catch (error) {
      // Use type assertion to get better type safety
      const axiosError = error as AxiosError;
      
      // Detailed error logging for debugging
      console.error('Challenge publish API error details:', {
        config: axiosError.config?.url,
        status: axiosError.response?.status,
        statusText: axiosError.response?.statusText,
        data: axiosError.response?.data
      });
      
      // Construct a meaningful error message
      let errorMessage = `Failed to publish challenge`;
      let errorDetails: Record<string, any> = {};
      
      if (axiosError.response) {
        const status = axiosError.response.status;
        const data = axiosError.response.data as any;
        errorDetails = {
          status,
          url: axiosError.config?.url,
          method: axiosError.config?.method?.toUpperCase(),
          responseData: data
        };
        
        if (status === 400) {
          // Bad request - likely not in draft status
          errorMessage = data?.message || 'Cannot publish challenge. It may not be in draft status.';
        } else if (status === 404) {
          errorMessage = `Challenge not found`;
        } else if (status === 500) {
          errorMessage = 'Server error: An internal server error occurred. The team has been notified.';
        } else if (status === 401 || status === 403) {
          errorMessage = data?.message || 'You do not have permission to publish this challenge.';
          
          // Add specific handling for permission errors
          if (data?.errorCode === 'NOT_CHALLENGE_OWNER') {
            errorMessage = 'You are not the owner of this challenge. Please contact support if you believe this is an error.';
          } else if (data?.errorCode === 'PROFILE_NOT_FOUND') {
            errorMessage = 'Your company profile could not be verified. Please complete your profile setup.';
          }
        } else {
          // Try to extract message from response if available
          if (data && data.message) {
            errorMessage += `: ${data.message}`;
          }
        }
      } else if (axiosError.request) {
        errorMessage = 'Unable to reach the server. Please check your connection.';
        errorDetails = {
          requestSent: true,
          responseReceived: false,
          url: axiosError.config?.url
        };
      } else {
        errorMessage = axiosError.message || 'An unknown error occurred';
      }
      
      // Log with better error details
      console.error('Challenge publish error:', {
        challengeId: id,
        message: errorMessage,
        details: errorDetails,
        originalError: axiosError
      });
      
      // Re-throw with a better message
      const enhancedError = new Error(errorMessage) as Error & { isHandled?: boolean; originalError?: any; details?: Record<string, any> };
      enhancedError.isHandled = true;
      enhancedError.originalError = axiosError;
      enhancedError.details = errorDetails;
      throw enhancedError;
    }
  }
} 