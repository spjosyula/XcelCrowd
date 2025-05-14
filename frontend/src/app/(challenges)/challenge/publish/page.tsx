"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { ChallengeView } from "@/components/challenges/ChallengeView";
import { ChallengeService } from "@/services/challenge.service";
import { Challenge } from "@/types/challenge";
import toast from "react-hot-toast";

export default function ChallengePublishPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const challengeId = searchParams.get("id");
  
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [loading, setLoading] = useState(true);
  const [publishLoading, setPublishLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchChallenge() {
      if (!challengeId) {
        setError("No challenge ID provided");
        setLoading(false);
        return;
      }

      try {
        const challengeData = await ChallengeService.getChallengeById(challengeId);
        setChallenge(challengeData);
      } catch (err: any) {
        console.error("Failed to fetch challenge:", err);
        setError(err.message || "Failed to load challenge. Please try again.");
      } finally {
        setLoading(false);
      }
    }

    fetchChallenge();
  }, [challengeId]);

  const handlePublish = async () => {
    if (!challengeId) return;
    
    setPublishLoading(true);
    setError(null);

    try {
      console.log(`Initiating publish for challenge: ${challengeId}`);
      
      // Call the publishChallenge API
      const publishedChallenge = await ChallengeService.publishChallenge(challengeId);
      
      console.log(`Challenge published successfully with status: ${publishedChallenge.status}`);
      
      // Show success toast
      toast.success("Challenge published successfully! Redirecting to dashboard...");
      
      // Wait briefly for toast to be visible before redirecting
      setTimeout(() => {
        router.push("/dashboard/company");
      }, 1500);
    } catch (err: any) {
      console.error("Failed to publish challenge:", err);
      
      // Specific error handling based on error content
      let errorMsg = err.message || "Failed to publish challenge. Please try again.";
      
      if (err.details?.status === 403) {
        errorMsg = "Permission error: " + errorMsg;
        toast.error(errorMsg);
      } else if (err.details?.status === 500) {
        errorMsg = "Server error: " + errorMsg;
        toast.error("A server error occurred. The team has been notified.");
      } else {
        toast.error(errorMsg);
      }
      
      setError(errorMsg);
      setPublishLoading(false);
    }
  };

  const handleRetry = async () => {
    // Clear error and try again
    setError(null);
    await handlePublish();
  };

  const handleReturnToDashboard = () => {
    router.push("/dashboard/company");
  };

  const handleDiagnostic = async () => {
    if (!challengeId) return;
    
    try {
      const response = await fetch(`/api/challenges/${challengeId}/ownership-check`, {
        method: 'GET',
        credentials: 'include'
      });
      
      const data = await response.json();
      
      // Display diagnostic results
      toast.success('Diagnostic completed, check console');
      console.log('Challenge ownership diagnostic results:', data);
      
      if (data.data?.ownership?.isOwner) {
        toast.success('You are confirmed as the owner of this challenge');
      } else {
        toast.error('Ownership verification failed');
      }
    } catch (err) {
      console.error('Diagnostic error:', err);
      toast.error('Failed to run diagnostic');
    }
  };

  if (loading) {
    return (
      <div className="w-full flex justify-center items-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-8">
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Error Publishing Challenge</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
        <div className="flex gap-4">
          <Button onClick={handleRetry}>Retry Publication</Button>
          <Button variant="outline" onClick={handleReturnToDashboard}>Return to Dashboard</Button>
          <Button 
            variant="secondary" 
            onClick={handleDiagnostic}
            className="ml-auto"
          >
            Run Diagnostic
          </Button>
        </div>
      </div>
    );
  }

  if (!challenge) {
    return (
      <div className="container mx-auto py-8">
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Not Found</AlertTitle>
          <AlertDescription>Challenge not found</AlertDescription>
        </Alert>
        <Button onClick={handleReturnToDashboard}>Return to Dashboard</Button>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8">
      <Card className="p-6 mb-8">
        <h1 className="text-2xl font-bold mb-6">Preview Your Challenge</h1>
        <p className="mb-6">
          This is how your challenge will appear to students. Review all details before publishing.
        </p>
        
        <div className="flex flex-wrap gap-4 mb-8">
          <Button 
            onClick={handlePublish} 
            disabled={publishLoading}
            className="bg-primary hover:bg-primary/90 text-primary-foreground"
          >
            {publishLoading ? <Spinner size="sm" className="mr-2" /> : null}
            Publish Challenge
          </Button>
          <Button variant="outline" onClick={handleReturnToDashboard}>
            Return to Dashboard
          </Button>
        </div>
      </Card>

      <ChallengeView challenge={challenge} isPreview={true} />
    </div>
  );
} 