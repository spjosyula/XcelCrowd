'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';

/**
 * QueryClient configured with optimal settings for our app
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // These are good defaults for most cases
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: process.env.NODE_ENV === 'production',
      refetchOnMount: true,
      refetchOnReconnect: true,
      retry: 1, // Only retry once by default
    },
    mutations: {
      // Use optimistic updates where possible and provide rollback on error
      onError: (err) => {
        console.error('Mutation error:', err);
      }
    }
  }
});

export function ReactQueryProvider({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60 * 1000, // 1 minute
        refetchOnWindowFocus: false,
      },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}


/**
 * Type-safe query keys for the application
 * This approach uses string literals for better type safety and simplicity
 */
export const queryKeys = {
  challenges: {
    all: ['challenges'] as const,
    list: (filters?: any) => ['challenges', 'list', filters] as const,
    detail: (id: string | number) => ['challenges', 'detail', id] as const,
  },
  profiles: {
    all: ['profiles'] as const,
    list: (filters?: any) => ['profiles', 'list', filters] as const,
    detail: (id: string | number) => ['profiles', 'detail', id] as const,
  },
  users: {
    all: ['users'] as const,
    list: (filters?: any) => ['users', 'list', filters] as const,
    detail: (id: string | number) => ['users', 'detail', id] as const,
  },
  auth: {
    all: ['auth'] as const,
    session: () => ['auth', 'session'] as const,
    user: () => ['auth', 'user'] as const,
  },
  solutions: {
    all: ['solutions'] as const,
    list: (filters?: any) => ['solutions', 'list', filters] as const,
    detail: (id: string | number) => ['solutions', 'detail', id] as const,
  },
};