import axios from 'axios';

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
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 Unauthorized - can be extended for token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      // You can implement token refresh here if needed
      // For now, just redirect to login
      if (typeof window !== 'undefined') {
        localStorage.removeItem('csrfToken');
        window.location.href = '/student/login';
      }
    }

    return Promise.reject(error);
  }
);

export default api; 