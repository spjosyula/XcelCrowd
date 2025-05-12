'use client';

import { useEffect } from 'react';
import { useAuth } from '@/context/AuthContext';
import RouteGuard from '@/components/auth/RouteGuard';
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  const { user, profile, logout } = useAuth();
  const router = useRouter();

  // Handle email verification reminder if email is not verified
  useEffect(() => {
    if (user && !user.isEmailVerified) {
      // Redirect to email verification page or show banner
    }
  }, [user, router]);

  return (
    <RouteGuard roles={['student']}>
      <div className="container py-8">
        <div className="flex flex-col gap-8">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold">Student Dashboard</h1>
            <button 
              onClick={() => logout()} 
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              Sign Out
            </button>
          </div>

          {user && profile && (
            <div className="grid gap-6 md:grid-cols-2">
              <div className="bg-card p-6 rounded-lg shadow-sm border">
                <h2 className="text-xl font-semibold mb-4">Welcome, {profile.firstName}!</h2>
                <div className="space-y-2">
                  <p><span className="font-medium">Email:</span> {user.email}</p>
                  <p><span className="font-medium">University:</span> {profile.university || 'Not specified'}</p>
                  <p><span className="font-medium">Email Verified:</span> {user.isEmailVerified ? 'Yes' : 'No'}</p>
                  {!user.isEmailVerified && (
                    <div className="mt-4">
                      <a 
                        href="/verify-email" 
                        className="text-primary hover:underline"
                      >
                        Verify your email to access all features
                      </a>
                    </div>
                  )}
                </div>
              </div>

              <div className="bg-card p-6 rounded-lg shadow-sm border">
                <h2 className="text-xl font-semibold mb-4">Quick Links</h2>
                <ul className="space-y-2">
                  <li>
                    <a 
                      href="/challenges" 
                      className="text-primary hover:underline"
                    >
                      Browse Challenges
                    </a>
                  </li>
                  <li>
                    <a 
                      href="/profile" 
                      className="text-primary hover:underline"
                    >
                      Update Profile
                    </a>
                  </li>
                  <li>
                    <a 
                      href="/submissions" 
                      className="text-primary hover:underline"
                    >
                      My Submissions
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </RouteGuard>
  );
} 