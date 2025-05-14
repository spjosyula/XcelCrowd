"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Container } from "@/components/ui/container";
import { ChallengeCard } from "@/components/challenges/ChallengeCard";
import { ChallengeFilters } from "@/components/challenges/ChallengeFilters";
import { Pagination } from "@/components/ui/pagination";
import { ChallengeService } from "@/services/challenge.service";
import { Challenge, ChallengeFilters as ChallengeFilterType, ChallengeStatus } from "@/types/challenge";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/AuthContext";
import { UserRole } from "@/types/user";

// Maximum number of retry attempts
const MAX_RETRIES = 3;

// Retry delay in milliseconds (starts at 1s, doubles each retry)
const INITIAL_RETRY_DELAY = 1000;

export default function ChallengePage() {
  const router = useRouter();
  const { user } = useAuth();
  
  // State for challenges data
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [totalChallenges, setTotalChallenges] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [hasNextPage, setHasNextPage] = useState<boolean>(false);
  
  // State for loading, error, and filters
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState<number>(0);
  const [isRetrying, setIsRetrying] = useState<boolean>(false);
  const [usingFallbackData, setUsingFallbackData] = useState<boolean>(false);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(true); // Assume authenticated initially
  const [filters, setFilters] = useState<ChallengeFilterType>({
    status: ChallengeStatus.ACTIVE,
    page: 1,
    limit: 8,
  });

  // Try to simplify the filters to reduce query complexity
  const getSimplifiedFilters = useCallback((currentFilters: ChallengeFilterType): ChallengeFilterType => {
    // Create a copy to avoid modifying the original
    const simplifiedFilters: ChallengeFilterType = { 
      page: currentFilters.page,
      limit: currentFilters.limit 
    };

    // Only include status if it's not 'all'
    if (currentFilters.status && currentFilters.status !== 'all') {
      simplifiedFilters.status = currentFilters.status;
    }
    
    // Only include search if it's not empty
    if (currentFilters.searchTerm && currentFilters.searchTerm.trim()) {
      simplifiedFilters.searchTerm = currentFilters.searchTerm;
    }

    // Only include difficulty if specified
    if (currentFilters.difficulty) {
      simplifiedFilters.difficulty = currentFilters.difficulty;
    }
    
    return simplifiedFilters;
  }, []);

  // Fetch challenges with retry logic
  const fetchChallenges = useCallback(async (shouldRetry = false, useSimplifiedFilters = false) => {
    if (shouldRetry) {
      setIsRetrying(true);
    } else {
      setIsLoading(true);
    }
    
    setError(null);
    setUsingFallbackData(false);
    
    try {
      // Use simplified filters if requested (reduces query complexity)
      const queryFilters = useSimplifiedFilters ? getSimplifiedFilters(filters) : filters;
      
      const result = await ChallengeService.getAllChallenges(queryFilters);
      
      // Reset retry count on success
      setRetryCount(0);
      setIsRetrying(false);
      
      setChallenges(result.data);
      setTotalChallenges(result.total);
      setTotalPages(Math.ceil(result.total / result.limit));
      setHasNextPage(result.hasNextPage || false);
      setIsAuthenticated(true);
    } catch (error) {
      console.error("Challenge fetch error:", error);
      
      // Handle authentication errors
      if ((error as any)?.message?.includes('permission') || 
          (error as any)?.message?.includes('authentication') ||
          (error as any)?.message?.includes('log in')) {
        setIsAuthenticated(false);
        setError((error as any).message || "You must be logged in as a student to view challenges.");
      } else if (shouldRetry && retryCount < MAX_RETRIES) {
        // Auto retry with exponential backoff
        const nextRetryCount = retryCount + 1;
        setRetryCount(nextRetryCount);
        
        const retryDelay = INITIAL_RETRY_DELAY * Math.pow(2, retryCount);
        
        // On first retry, try with simplified filters to avoid backend query issues
        const shouldUseSimplifiedFilters = nextRetryCount === 1;
        
        setTimeout(() => fetchChallenges(true, shouldUseSimplifiedFilters), retryDelay);
        
        // Set a temporary message while retrying
        setError(`Error loading challenges. Retrying... (Attempt ${nextRetryCount}/${MAX_RETRIES})`);
      } else {
        // Set final error after retries exhausted
        setError((error as any).message || "Failed to load challenges. Please try again later.");
        setIsRetrying(false);
        
        // Use empty data after all retries fail
        setChallenges([]);
        setTotalChallenges(0);
        setTotalPages(1);
        setHasNextPage(false);
        setUsingFallbackData(true);
      }
    } finally {
      if (!isRetrying) {
        setIsLoading(false);
      }
    }
  }, [filters, retryCount, getSimplifiedFilters, isRetrying]);

  // Handle filter changes
  const handleFilterChange = useCallback((newFilters: ChallengeFilterType) => {
    // If we're using fallback data, clear it when filters change
    if (usingFallbackData) {
      setUsingFallbackData(false);
    }
    
    setFilters(newFilters);
    // Reset retry count when filters change
    setRetryCount(0);
  }, [usingFallbackData]);

  // Handle page change
  const handlePageChange = useCallback((page: number) => {
    // If we're using fallback data, don't allow pagination
    if (usingFallbackData) {
      return;
    }
    
    setFilters(prev => ({
      ...prev,
      page,
    }));
    // Reset retry count when page changes
    setRetryCount(0);
  }, [usingFallbackData]);

  // Manual retry handler
  const handleRetry = useCallback(() => {
    // If we're using fallback data, switch back to real data fetch
    if (usingFallbackData) {
      setUsingFallbackData(false);
    }
    
    // Try with simplified filters on manual retry
    fetchChallenges(true, true);
  }, [fetchChallenges, usingFallbackData]);

  // Navigation handlers
  const handleLogin = useCallback(() => {
    router.push("/login");
  }, [router]);

  const handleRegister = useCallback(() => {
    router.push("/register");
  }, [router]);

  const handleCreateChallenge = useCallback(() => {
    // Note: This should eventually be a POST request to /challenge
    // instead of a separate route, but we'll keep it for now
    router.push("/challenge/create");
  }, [router]);

  // Fetch challenges when filters change
  useEffect(() => {
    fetchChallenges();
  }, [filters, fetchChallenges]);

  // If not authenticated, show login prompt
  if (!isAuthenticated) {
    return (
      <Container>
        <div className="py-8">
          <h1 className="text-3xl font-bold mb-6">Challenges</h1>
          
          <div className="bg-yellow-50 border border-yellow-100 rounded-lg p-6 mb-8">
            <h3 className="text-lg font-medium mb-2">Authentication Required</h3>
            <p className="text-gray-600 mb-4">
              You need to be logged in as a student or admin to view challenges.
            </p>
            <div className="flex gap-4">
              <Button onClick={handleLogin}>
                Log In
              </Button>
              <Button variant="outline" onClick={handleRegister}>
                Register
              </Button>
            </div>
          </div>
        </div>
      </Container>
    );
  }

  // Determine if we're in a retry state (to show special UI)
  const isInRetryState = isRetrying || (error?.includes('Retrying') ?? false);

  return (
    <Container>
      <div className="py-8">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Challenges</h1>
          {user && user.role === UserRole.COMPANY && (
            <Button 
              variant="royal" 
              onClick={handleCreateChallenge}
              className="flex items-center gap-2"
              aria-label="Create Challenge"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clipRule="evenodd" />
              </svg>
              Create Challenge
            </Button>
          )}
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Filters Sidebar */}
          <div className="lg:col-span-1">
            <ChallengeFilters 
              filters={filters} 
              onFilterChange={handleFilterChange} 
            />
          </div>
          
          {/* Challenge Cards */}
          <div className="lg:col-span-3">
            {error && !usingFallbackData && (
              <Alert 
                variant={isInRetryState ? "default" : "destructive"} 
                className="mb-6"
              >
                <div className="flex flex-col">
                  <div className="mb-2">{error}</div>
                  {!isRetrying && (
                    <Button
                      size="sm"
                      onClick={handleRetry}
                      variant="outline"
                      className="self-start"
                      disabled={isInRetryState}
                    >
                      {isInRetryState ? "Retrying..." : "Retry Now"}
                    </Button>
                  )}
                </div>
              </Alert>
            )}
            
            {isLoading && !isRetrying ? (
              // Loading skeleton
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {Array.from({ length: 4 }).map((_, index) => (
                  <div
                    key={index}
                    className="animate-pulse bg-gray-100 rounded-lg h-64"
                  ></div>
                ))}
              </div>
            ) : challenges.length > 0 ? (
              <div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {challenges.map((challenge) => (
                    <ChallengeCard key={challenge._id} challenge={challenge} />
                  ))}
                </div>
                
                {!usingFallbackData && (
                  <Pagination 
                    currentPage={filters.page || 1} 
                    totalPages={totalPages}
                    onPageChange={handlePageChange}
                    hasNextPage={hasNextPage}
                  />
                )}
              </div>
            ) : (
              <div className="text-center py-12">
                <h3 className="text-lg font-medium mb-2">No challenges found</h3>
                <p className="text-gray-500 mb-4">
                  {error 
                    ? "Please try again or adjust your filters." 
                    : "Try adjusting your filters or check back later for new challenges."}
                </p>
                {error && !usingFallbackData && (
                  <Button onClick={handleRetry} disabled={isRetrying}>
                    {isRetrying ? "Retrying..." : "Try Again"}
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </Container>
  );
}

