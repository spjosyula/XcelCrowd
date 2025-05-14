'use server'

import axios from 'axios';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { cookieUtils } from '@/lib/cookies';
import { revalidatePath } from 'next/cache';

// Create server-side axios instance
const serverApi = axios.create({
  baseURL: process.env.API_URL || 'http://localhost:5000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Error handling for server actions
export class ServerActionError extends Error {
  statusCode?: number;
  
  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'ServerActionError';
    this.statusCode = statusCode;
  }
}

/**
 * Securely make an API request from the server with cookies
 */
export async function secureApiRequest<T>(
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  endpoint: string,
  data?: unknown,
  options?: {
    revalidate?: string[];
    redirectOnUnauthorized?: boolean;
    redirectTo?: string;
  }
): Promise<T> {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('XcelCrowd-Session')?.value;
  
  try {
    const response = await serverApi({
      method,
      url: endpoint,
      data: method !== 'GET' ? data : undefined,
      params: method === 'GET' ? data : undefined,
      headers: {
        Cookie: sessionCookie ? `XcelCrowd-Session=${sessionCookie}` : '',
      },
    });
    
    // Revalidate paths if specified
    if (options?.revalidate) {
      options.revalidate.forEach(path => revalidatePath(path));
    }
    
    return response.data.data;
  } catch (error: any) {
    console.error(`API request error (${method} ${endpoint}):`, error.response?.data || error.message);
    
    // Handle authentication errors
    if (error.response?.status === 401 || error.response?.status === 403) {
      // Clear auth cookies
      cookieUtils.clearAuthCookies();
      
      // Redirect to login if specified
      if (options?.redirectOnUnauthorized) {
        const redirectPath = options.redirectTo || '/login';
        redirect(redirectPath);
      }
    }
    
    // Throw formatted error
    throw new ServerActionError(
      error.response?.data?.message || 'Something went wrong with the API request',
      error.response?.status
    );
  }
}

/**
 * Fetch data from the API securely from the server
 */
export async function fetchFromApi<T>(
  endpoint: string,
  params?: Record<string, any>,
  options?: {
    revalidate?: string[];
    redirectOnUnauthorized?: boolean;
  }
): Promise<T> {
  return secureApiRequest<T>('GET', endpoint, params, options);
}

/**
 * Submit data to the API securely from the server
 */
export async function submitToApi<T>(
  endpoint: string,
  data: any,
  options?: {
    revalidate?: string[];
    redirectOnUnauthorized?: boolean;
    redirectTo?: string;
  }
): Promise<T> {
  return secureApiRequest<T>('POST', endpoint, data, options);
}

/**
 * Update data through the API securely from the server
 */
export async function updateThroughApi<T>(
  endpoint: string,
  data: any,
  options?: {
    revalidate?: string[];
    redirectOnUnauthorized?: boolean;
    method?: 'PUT' | 'PATCH';
  }
): Promise<T> {
  return secureApiRequest<T>(options?.method || 'PUT', endpoint, data, options);
}

/**
 * Delete data through the API securely from the server
 */
export async function deleteFromApi<T>(
  endpoint: string,
  options?: {
    revalidate?: string[];
    redirectOnUnauthorized?: boolean;
  }
): Promise<T> {
  return secureApiRequest<T>('DELETE', endpoint, undefined, options);
} 