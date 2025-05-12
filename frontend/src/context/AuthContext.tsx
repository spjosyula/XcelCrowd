'use client'

import React, { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import authService, { 
  AuthResponse, 
  LoginCredentials, 
  StudentRegistrationData 
} from '@/services/auth.service';

interface User {
  _id: string;
  email: string;
  role: string;
  isEmailVerified: boolean;
}

interface UserProfile {
  _id: string;
  firstName: string;
  lastName: string;
  university?: string;
  [key: string]: any;
}

interface AuthContextType {
  user: User | null;
  profile: UserProfile | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  loginStudent: (credentials: LoginCredentials) => Promise<void>;
  registerStudent: (data: StudentRegistrationData) => Promise<void>;
  logout: () => Promise<void>;
  error: string | null;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  // Check for user session on initial load
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Implement session check here
        // For now, just check if csrfToken exists
        const csrfToken = localStorage.getItem('csrfToken');
        
        if (csrfToken) {
          // TODO: Implement actual session validation with backend
          // For now, we'll use localStorage until session API is implemented
          const userData = localStorage.getItem('user');
          const profileData = localStorage.getItem('profile');
          
          if (userData && profileData) {
            setUser(JSON.parse(userData));
            setProfile(JSON.parse(profileData));
          } else {
            // Clear invalid state
            localStorage.removeItem('csrfToken');
            localStorage.removeItem('user');
            localStorage.removeItem('profile');
          }
        }
      } catch (err) {
        console.error('Session check failed:', err);
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, []);

  const loginStudent = async (credentials: LoginCredentials) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await authService.loginStudent(credentials);
      handleAuthSuccess(response);
      router.push('/dashboard/student'); // Redirect to student dashboard after login
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const registerStudent = async (data: StudentRegistrationData) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await authService.registerStudent(data);
      handleAuthSuccess(response);
      router.push('/student/verify-email'); // Keep redirecting to email verification
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    
    try {
      await authService.logout();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      // Clear auth state regardless of API response
      localStorage.removeItem('csrfToken');
      localStorage.removeItem('user');
      localStorage.removeItem('profile');
      setUser(null);
      setProfile(null);
      setIsLoading(false);
      router.push('/');
    }
  };

  const clearError = () => setError(null);

  const handleAuthSuccess = (response: AuthResponse) => {
    if (response.user) {
      setUser(response.user);
      localStorage.setItem('user', JSON.stringify(response.user));
    }
    
    if (response.profile) {
      setProfile(response.profile);
      localStorage.setItem('profile', JSON.stringify(response.profile));
    }
    
    if (response.csrfToken) {
      localStorage.setItem('csrfToken', response.csrfToken);
    }
  };

  const value: AuthContextType = {
    user,
    profile,
    isLoading,
    isAuthenticated: !!user,
    loginStudent,
    registerStudent,
    logout,
    error,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext; 