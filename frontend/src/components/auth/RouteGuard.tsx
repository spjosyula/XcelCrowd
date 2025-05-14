import { ReactNode, useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { UserRole } from '@/types/user';

interface RouteGuardProps {
  children: ReactNode;
  roles?: UserRole[];
}

/**
 * Route Guard component to protect routes that require authentication
 * @param children - The protected route content
 * @param roles - Optional roles that are allowed to access the route
 */
export function RouteGuard({ children, roles }: RouteGuardProps) {
  const { user, isLoading, isAuthenticated } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Auth state is still loading, do nothing yet
    if (isLoading) return;

    // If not authenticated, redirect to login
    if (!isAuthenticated) {
      // Preserve the attempted URL for redirect after login
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('redirectAfterLogin', pathname);
      }
      router.replace('/login');
      return;
    }

    // If roles are specified, check if user has required role
    if (roles && roles.length > 0 && user) {
      if (!roles.includes(user.role as UserRole)) {
        // User doesn't have required role, redirect to appropriate page
        if (user.role === UserRole.STUDENT) {
          router.replace('/dashboard/student');
        } else if (user.role === UserRole.COMPANY) {
          router.replace('/dashboard/company');
        } else if (user.role === UserRole.ARCHITECT) {
          router.replace('/dashboard/architect');
        } else {
          router.replace('/');
        }
      }
    }
  }, [isLoading, isAuthenticated, user, roles, router, pathname]);

  // Show nothing while checking authentication
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  // If not authenticated or doesn't have required role, show nothing (will be redirected)
  if (!isAuthenticated) {
    return null;
  }

  // If roles are specified and user doesn't have any required role, show nothing
  if (roles && roles.length > 0 && user && !roles.includes(user.role as UserRole)) {
    return null;
  }

  // Otherwise, render the protected content
  return <>{children}</>;
}

export default RouteGuard; 