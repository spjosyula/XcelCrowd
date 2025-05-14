import axios, { AxiosError } from 'axios';

// Create axios instance with default configuration
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for cookies/CSRF
  // Add a timeout to prevent hanging requests
  timeout: 10000,
  // Ensure data isn't transformed in a way that could affect MongoDB ObjectId validation
  transformRequest: [(data) => {
    return JSON.stringify(data);
  }],
});

// Add request interceptor for CSRF token
api.interceptors.request.use(
  (config) => {
    // Get CSRF token from localStorage if available
    const csrfToken = typeof window !== 'undefined' 
      ? localStorage.getItem('csrfToken') 
      : null;
    
    // If token exists, add it to headers
    if (csrfToken) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error: AxiosError) => {
    // Safe access to request configuration
    const url = error.config?.url || 'Unknown URL';
    const method = error.config?.method?.toUpperCase() || 'Unknown Method';
    
    try {
      // Create a safe error log object with proper null checks
      const errorLog: Record<string, any> = {
        url,
        method,
        message: error.message || 'Unknown error'
      };

      // Only add response data if it exists and is accessible
      if (error.response) {
        errorLog.status = error.response.status;
        errorLog.statusText = error.response.statusText || 'No status text';
        
        // Safely add response data
        if (error.response.data) {
          // Check if data is an empty object
          const isEmptyObject = typeof error.response.data === 'object' && 
                               Object.keys(error.response.data).length === 0;
          
          if (isEmptyObject) {
            errorLog.data = { 
              note: 'Empty response object received from server',
              raw: JSON.stringify(error.response.data)
            };
          } else {
            errorLog.data = typeof error.response.data === 'object' 
              ? error.response.data 
              : { rawData: String(error.response.data) };
          }
        } else {
          errorLog.data = { note: 'No response data received' };
        }
        
        // Add request details to help with debugging
        if (error.config) {
          errorLog.requestDetails = {
            headers: error.config.headers,
            params: error.config.params,
            timeout: error.config.timeout,
            withCredentials: error.config.withCredentials
          };
        }
      } else if (error.request) {
        // The request was made but no response was received
        errorLog.requestSent = true;
        errorLog.responseReceived = false;
        errorLog.networkError = true;
        errorLog.timeoutError = error.code === 'ECONNABORTED';
      }

      console.error(`API Error (${method} ${url}):`, errorLog);
    } catch (loggingError) {
      // Fallback if error logging itself fails
      console.error('Failed to log API error details:', loggingError);
      console.error('Original error:', error.message);
    }

    // Handle authentication errors
    if (error.response?.status === 401 || error.response?.status === 403) {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('csrfToken');
        
        // Determine appropriate redirect based on URL
        if (url.includes('/challenges')) {
          window.location.href = '/login';
        } else {
          window.location.href = '/login';
        }
      }
    }

    return Promise.reject(error);
  }
);

export default api; 