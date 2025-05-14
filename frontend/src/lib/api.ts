import api from '@/services/api';
import { AxiosError, AxiosRequestConfig} from 'axios';

/**
 * Standard API response format from our backend
 */
export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  errors?: string[];
}

/**
 * API error with additional context
 */
export class ApiError extends Error {
  statusCode: number;
  errors?: string[];
  originalError: any;
  
  constructor(message: string, statusCode: number, originalError: any, errors?: string[]) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.errors = errors;
    this.originalError = originalError;
  }
}

/**
 * Typed HTTP client for making API requests with automatic error handling
 */
export const httpClient = {
  /**
   * Make a GET request
   */
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await api.get<ApiResponse<T>>(url, config);
      return response.data.data;
    } catch (error) {
      throw handleApiError(error);
    }
  },
  
  /**
   * Make a POST request
   */
  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await api.post<ApiResponse<T>>(url, data, config);
      return response.data.data;
    } catch (error) {
      throw handleApiError(error);
    }
  },
  
  /**
   * Make a PUT request
   */
  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await api.put<ApiResponse<T>>(url, data, config);
      return response.data.data;
    } catch (error) {
      throw handleApiError(error);
    }
  },
  
  /**
   * Make a PATCH request
   */
  async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await api.patch<ApiResponse<T>>(url, data, config);
      return response.data.data;
    } catch (error) {
      throw handleApiError(error);
    }
  },
  
  /**
   * Make a DELETE request
   */
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    try {
      const response = await api.delete<ApiResponse<T>>(url, config);
      return response.data.data;
    } catch (error) {
      throw handleApiError(error);
    }
  }
};

/**
 * Standard error handling for API requests
 */
function handleApiError(error: any): never {
  const axiosError = error as AxiosError<ApiResponse<any>>;
  
  let message = 'An unexpected error occurred';
  let statusCode = 500;
  let errors: string[] | undefined;
  
  if (axiosError.response) {
    // The request was made and the server responded with a status code
    statusCode = axiosError.response.status;
    
    // Try to get error message from response
    const responseData = axiosError.response.data;
    if (responseData) {
      message = responseData.message || getMessage(statusCode);
      errors = responseData.errors;
    } else {
      message = getMessage(statusCode);
    }
  } else if (axiosError.request) {
    // The request was made but no response was received
    message = 'No response received from server. Please check your connection.';
    statusCode = 0;
  } else {
    // Something happened in setting up the request
    message = axiosError.message || 'Failed to make request';
  }
  
  throw new ApiError(message, statusCode, axiosError, errors);
}

/**
 * Get default message for HTTP status code
 */
function getMessage(statusCode: number): string {
  switch (statusCode) {
    case 400:
      return 'Bad request. Please check your input.';
    case 401:
      return 'You are not authenticated. Please login.';
    case 403:
      return 'You do not have permission to perform this action.';
    case 404:
      return 'Resource not found.';
    case 409:
      return 'Conflict with existing data.';
    case 422:
      return 'Validation failed.';
    case 429:
      return 'Too many requests. Please try again later.';
    case 500:
      return 'Server error. Please try again later.';
    default:
      return `Error with status code: ${statusCode}`;
  }
} 