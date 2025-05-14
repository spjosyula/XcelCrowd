import { cookies } from 'next/headers';
import { ReadonlyRequestCookies } from 'next/dist/server/web/spec-extension/adapters/request-cookies';

const COOKIE_PREFIX = 'XcelCrowd';
const SESSION_COOKIE = `${COOKIE_PREFIX}-Session`;
const CSRF_COOKIE = `${COOKIE_PREFIX}-CSRF-Token`;
const USER_COOKIE = `${COOKIE_PREFIX}-User`;

// Common cookie options
const getSecureCookieOptions = (maxAge: number = 7 * 24 * 60 * 60) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAge, // Default is 1 week
  path: '/',
});

export const cookieUtils = {
  // Set a secure HTTP-only cookie
  setSecureCookie: async (name: string, value: string, maxAge?: number) => {
    const cookieStore = await cookies();
    const options = getSecureCookieOptions(maxAge);
    cookieStore.set(name, value, options);
  },
  
  // Get a cookie value
  getCookie: async (name: string, cookieStore?: ReadonlyRequestCookies) => {
    const store = cookieStore || await cookies();
    return store.get(name)?.value;
  },
  
  // Delete a cookie
  deleteCookie: async (name: string) => {
    const cookieStore = await cookies();
    cookieStore.delete(name);
  },
  
  // Set authentication cookies
  setAuthCookies: async (sessionToken: string, csrfToken: string, userData: string, maxAge?: number) => {
    const cookieStore = await cookies();
    const options = getSecureCookieOptions(maxAge);
    
    // Session cookie - HTTP only, secure
    cookieStore.set(SESSION_COOKIE, sessionToken, options);
    
    // CSRF token - accessible from JS
    cookieStore.set(CSRF_COOKIE, csrfToken, {
      ...options,
      httpOnly: false, // Accessible to JS for API calls
    });
    
    // User data - accessible from JS, but minimal info
    cookieStore.set(USER_COOKIE, userData, {
      ...options,
      httpOnly: false, // Accessible to JS for API calls
    });
  },
  
  // Clear all authentication cookies
  clearAuthCookies: async () => {
    const cookieStore = await cookies();
    cookieStore.delete(SESSION_COOKIE);
    cookieStore.delete(CSRF_COOKIE);
    cookieStore.delete(USER_COOKIE);
  },
  
  // Check if user has authentication cookies
  hasAuthCookies: async (cookieStore?: ReadonlyRequestCookies) => {
    const store = cookieStore || await cookies();
    return !!store.get(SESSION_COOKIE) && !!store.get(CSRF_COOKIE);
  },
}; 