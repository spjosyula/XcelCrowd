"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Container } from "@/components/ui/container";
import { Alert } from "@/components/ui/alert";
import { ChallengeService } from "@/services/challenge.service";
import { Challenge, ChallengeDifficulty, ChallengeStatus, ChallengeVisibility } from "@/types/challenge";
import { formatDate } from "@/lib/utils";

// Maximum number of retry attempts
const MAX_RETRIES = 3;

// Retry delay in milliseconds (starts at 1s, doubles each retry)
const INITIAL_RETRY_DELAY = 1000;

// Fallback challenge to use when API fails
const FALLBACK_CHALLENGE: Challenge = {
  _id: "fallback-detail",
  title: "Sample Challenge: Urban Innovation Hub",
  description: "Design a multi-function urban innovation hub that connects university research with industry applications. The hub should facilitate collaboration between students, faculty, and industry partners while addressing urban challenges.\n\nThe design should include physical spaces, digital infrastructure, and operational models that make the hub sustainable and impactful.",
  company: "acme-corp",
  requirements: [
    "Detailed architectural and functional design",
    "Implementation plan including timeline and resource requirements",
    "Budget proposal and potential funding sources",
    "Metrics for measuring impact and success"
  ],
  resources: [
    "https://example.com/urban-innovation-models",
    "https://example.com/university-industry-collaboration"
  ],
  rewards: "1st Place: $3,000, 2nd Place: $1,500, 3rd Place: $500",
  deadline: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000).toISOString(), // 45 days from now
  status: ChallengeStatus.ACTIVE,
  difficulty: ChallengeDifficulty.ADVANCED,
  category: ["Urban Planning", "Innovation", "Education"],
  maxParticipants: 50,
  currentParticipants: 18,
  publishedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(), // 15 days ago
  tags: ["Urban Planning", "Innovation", "University", "Industry Collaboration"],
  maxApprovedSolutions: 5,
  approvedSolutionsCount: 0,
  visibility: ChallengeVisibility.PUBLIC,
  isCompanyVisible: true,
  createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(), // 20 days ago
  updatedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString() // 10 days ago
};

// Helper function to get badge variant based on challenge status
const getStatusVariant = (status: ChallengeStatus) => {
  switch (status) {
    case ChallengeStatus.ACTIVE:
      return "success";
    case ChallengeStatus.CLOSED:
      return "warning";
    case ChallengeStatus.COMPLETED:
      return "secondary";
    case ChallengeStatus.DRAFT:
      return "default";
    default:
      return "default";
  }
};

// Helper function to get badge variant based on challenge difficulty
const getDifficultyVariant = (difficulty: ChallengeDifficulty) => {
  switch (difficulty) {
    case ChallengeDifficulty.BEGINNER:
      return "primary";
    case ChallengeDifficulty.INTERMEDIATE:
      return "info";
    case ChallengeDifficulty.ADVANCED:
      return "warning";
    case ChallengeDifficulty.EXPERT:
      return "danger";
    default:
      return "default";
  }
};

export default function ChallengeDetailPage() {
  const params = useParams();
  const router = useRouter();
  const challengeId = params.id as string;
  
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState<number>(0);
  const [isRetrying, setIsRetrying] = useState<boolean>(false);
  const [usingFallbackData, setUsingFallbackData] = useState<boolean>(false);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(true); // Assume authenticated initially

  // Fetch challenge with retry logic
  const fetchChallenge = useCallback(async (shouldRetry = false) => {
    if (!challengeId) return;
    
    if (shouldRetry) {
      setIsRetrying(true);
    } else {
      setIsLoading(true);
    }
    
    setError(null);
    setUsingFallbackData(false);
    
    try {
      const data = await ChallengeService.getChallengeById(challengeId);
      
      // Reset retry count on success
      setRetryCount(0);
      setIsRetrying(false);
      
      setChallenge(data);
      setIsAuthenticated(true);
    } catch (err: unknown) {
      console.error("Challenge detail fetch error:", err);

      let errorMessage = "Failed to load challenge details. Please try again later.";
      if (typeof err === "object" && err !== null && "message" in err && typeof (err as { message?: string }).message === "string") {
        errorMessage = (err as { message: string }).message;
      }

      // Handle authentication errors
      if (
        typeof err === "object" &&
        err !== null &&
        "message" in err &&
        typeof (err as { message?: string }).message === "string" &&
        (
          (err as { message: string }).message.includes('permission') ||
          (err as { message: string }).message.includes('authentication') ||
          (err as { message: string }).message.includes('log in')
        )
      ) {
        setIsAuthenticated(false);
        setError(errorMessage || "You must be logged in as a student to view this challenge.");
      } else if (shouldRetry && retryCount < MAX_RETRIES) {
        // Auto retry with exponential backoff
        const nextRetryCount = retryCount + 1;
        setRetryCount(nextRetryCount);
        
        const retryDelay = INITIAL_RETRY_DELAY * Math.pow(2, retryCount);
        setTimeout(() => fetchChallenge(true), retryDelay);
        
        // Set a temporary message while retrying
        setError(`Error loading challenge. Retrying... (Attempt ${nextRetryCount}/${MAX_RETRIES})`);
      } else {
        // Set final error after retries exhausted
        setError(errorMessage);
        setIsRetrying(false);
        
        // Use fallback data after all retries fail
        // Don't show fallback for 404 errors (challenge not found)
        if (!errorMessage.includes('not found')) {
          setChallenge(FALLBACK_CHALLENGE);
          setUsingFallbackData(true);
        }
      }
    } finally {
      if (!isRetrying) {
        setIsLoading(false);
      }
    }
  }, [challengeId, retryCount, isRetrying]);

  // Manual retry handler
  const handleRetry = useCallback(() => {
    // If we're using fallback data, switch back to real data fetch
    if (usingFallbackData) {
      setUsingFallbackData(false);
    }
    
    fetchChallenge(true);
  }, [fetchChallenge, usingFallbackData]);

  // Format dates
  const formatDeadline = useCallback((dateString?: string) => {
    if (!dateString) return "Not set";
    return formatDate(new Date(dateString));
  }, []);
  
  // Handler for back button
  const handleBack = useCallback(() => {
    router.back();
  }, [router]);
  
  // Handler for apply button (to be implemented)
  const handleApply = useCallback(() => {
    // TODO: Implement application logic
    alert("Apply for challenge functionality will be implemented soon!");
  }, []);

  // Navigation handlers
  const handleLogin = useCallback(() => {
    router.push("/login");
  }, [router]);

  const handleRegister = useCallback(() => {
    router.push("/register");
  }, [router]);

  // Fetch challenge data on mount and when ID changes
  useEffect(() => {
    if (challengeId) {
      fetchChallenge();
    }
  }, [challengeId, fetchChallenge]);

  // If not authenticated, show login prompt
  if (!isAuthenticated) {
    return (
      <Container>
        <div className="py-8">
          <Button onClick={handleBack} variant="outline" className="mb-6">
            Back
          </Button>
          
          <div className="bg-yellow-50 border border-yellow-100 rounded-lg p-6 mb-8">
            <h3 className="text-lg font-medium mb-2">Authentication Required</h3>
            <p className="text-gray-600 mb-4">
              You need to be logged in as a student or admin to view challenge details.
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

  // Loading state
  if (isLoading && !isRetrying) {
    return (
      <Container>
        <div className="py-8">
          <Button onClick={handleBack} variant="outline" className="mb-6">
            Back
          </Button>
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/3 mb-6"></div>
            <div className="h-64 bg-gray-200 rounded mb-4"></div>
            <div className="h-32 bg-gray-200 rounded"></div>
          </div>
        </div>
      </Container>
    );
  }

  // Error state with no fallback data
  if ((error && !isInRetryState && !usingFallbackData) || (!challenge && !usingFallbackData)) {
    return (
      <Container>
        <div className="py-8">
          <Button onClick={handleBack} variant="outline" className="mb-6">
            Back to Challenges
          </Button>
          
          <Alert 
            variant="destructive" 
            className="mb-4"
          >
            {error || "Challenge not found"}
          </Alert>
          
          <Button 
            onClick={handleRetry} 
            disabled={isRetrying}
          >
            {isRetrying ? "Retrying..." : "Try Again"}
          </Button>
        </div>
      </Container>
    );
  }

  // We should now have either real data or fallback data
  const displayChallenge = challenge || FALLBACK_CHALLENGE;

  // Calculate if deadline is passed
  const isDeadlinePassed = new Date(displayChallenge.deadline) < new Date();
  // Calculate spots remaining
  const spotsRemaining = displayChallenge.maxParticipants 
    ? displayChallenge.maxParticipants - displayChallenge.currentParticipants 
    : "Unlimited";

  return (
    <Container>
      <div className="py-8">
        <Button 
          onClick={handleBack} 
          variant="outline" 
          className="mb-6"
        >
          Back to Challenges
        </Button>
        
        {isInRetryState && (
          <Alert className="mb-4">
            {error}
          </Alert>
        )}
        
        {usingFallbackData && (
          <Alert variant="warning" className="mb-4">
            <div className="flex flex-col">
              <p className="font-medium">Showing sample challenge data</p>
              <p className="text-sm">We encountered an issue retrieving this challenge.</p>
              <Button 
                size="sm" 
                variant="outline"
                className="self-start mt-2"
                onClick={handleRetry}
              >
                Try Again
              </Button>
            </div>
          </Alert>
        )}
        
        <div className="flex flex-wrap gap-2 mb-4">
          <Badge variant={getStatusVariant(displayChallenge.status)}>
            {displayChallenge.status.charAt(0).toUpperCase() + displayChallenge.status.slice(1)}
          </Badge>
          <Badge variant={getDifficultyVariant(displayChallenge.difficulty)}>
            {displayChallenge.difficulty.charAt(0).toUpperCase() + displayChallenge.difficulty.slice(1)}
          </Badge>
          {displayChallenge.category.map((cat, index) => (
            <Badge key={index} variant="default">
              {cat}
            </Badge>
          ))}
        </div>
        
        <h1 className="text-3xl font-bold mb-4">{displayChallenge.title}</h1>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="lg:col-span-2">
            <Card className="p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Description</h2>
              <div className="prose max-w-none">
                <p className="whitespace-pre-line">{displayChallenge.description}</p>
              </div>
            </Card>
            
            <Card className="p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Requirements</h2>
              <ul className="list-disc pl-6 space-y-2">
                {displayChallenge.requirements.map((req, index) => (
                  <li key={index}>{req}</li>
                ))}
              </ul>
            </Card>
            
            {displayChallenge.resources && displayChallenge.resources.length > 0 && (
              <Card className="p-6">
                <h2 className="text-xl font-semibold mb-4">Resources</h2>
                <ul className="list-disc pl-6 space-y-2">
                  {displayChallenge.resources.map((resource, index) => (
                    <li key={index}>
                      <a 
                        href={resource}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline"
                      >
                        {resource}
                      </a>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </div>
          
          <div className="lg:col-span-1">
            <Card className="p-6 mb-6">
              <h2 className="text-xl font-semibold mb-4">Challenge Details</h2>
              
              <div className="space-y-4">
                <div>
                  <span className="text-gray-500 block">Deadline</span>
                  <span className={`font-medium ${isDeadlinePassed ? 'text-red-600' : ''}`}>
                    {formatDeadline(displayChallenge.deadline)}
                    {isDeadlinePassed && ' (Passed)'}
                  </span>
                </div>
                
                <div>
                  <span className="text-gray-500 block">Participants</span>
                  <span className="font-medium">
                    {displayChallenge.currentParticipants} 
                    {displayChallenge.maxParticipants ? ` / ${displayChallenge.maxParticipants}` : ''}
                  </span>
                </div>
                
                <div>
                  <span className="text-gray-500 block">Spots Remaining</span>
                  <span className="font-medium">
                    {spotsRemaining}
                  </span>
                </div>
                
                {displayChallenge.rewards && (
                  <div>
                    <span className="text-gray-500 block">Rewards</span>
                    <span className="font-medium">{displayChallenge.rewards}</span>
                  </div>
                )}
                
                {displayChallenge.tags.length > 0 && (
                  <div>
                    <span className="text-gray-500 block">Tags</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {displayChallenge.tags.map((tag, index) => (
                        <Badge key={index} variant="default" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                
                <div>
                  <span className="text-gray-500 block">Published</span>
                  <span className="font-medium">
                    {displayChallenge.publishedAt ? formatDeadline(displayChallenge.publishedAt) : 'Not published'}
                  </span>
                </div>
              </div>
            </Card>
            
            <Button 
              onClick={handleApply} 
              className="w-full" 
              size="lg"
              disabled={isDeadlinePassed || displayChallenge.status !== ChallengeStatus.ACTIVE || usingFallbackData}
            >
              {usingFallbackData ? 'Sample Challenge' :
               isDeadlinePassed ? 'Deadline Passed' : 
               displayChallenge.status !== ChallengeStatus.ACTIVE ? 'Not Available' : 
               'Apply to Challenge'}
            </Button>
          </div>
        </div>
      </div>
    </Container>
  );
}


