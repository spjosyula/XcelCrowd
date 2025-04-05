/**
 * Route configuration for the application
 * Centralized definition of public and protected paths
 */
export const routeConfig = {
    /**
     * Paths that don't require authentication
     */
    publicPaths: [
      '/api/auth/student/login',
      '/api/auth/company/login',
      '/api/auth/admin/login', 
      '/api/auth/student/register',
      '/api/auth/architect/login',
      '/api/auth/company/register',
      '/api/auth/forgot-password',
      '/api/auth/reset-password',
      '/api/health',
      '/' 
    ],
    
    /**
     * Test if a path is public (doesn't require authentication)
     * @param path - The path to check
     * @returns Whether the path is public
     */
    isPublicPath: (path: string): boolean => {
      return routeConfig.publicPaths.includes(path) || 
             path.startsWith('/static/') ||
             path.startsWith('/assets/');
    }
  };