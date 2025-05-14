"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { CreateChallengeForm } from "@/components/challenges/CreateChallengeForm";
import { RouteGuard } from "@/components/auth/RouteGuard";
import { UserRole } from "@/types/user";

export default function CreateChallengePage() {
  const router = useRouter();
  
  // For proper API structure, we should eventually move the form submission 
  // directly to the /challenge endpoint with a POST request
  useEffect(() => {
    console.warn("Note: This route will be deprecated. Challenge creation should use POST /api/challenges.");
  }, []);
  
  return (
    <RouteGuard roles={[UserRole.COMPANY]}>
      <div className="container mx-auto py-8">
        <h1 className="text-2xl font-bold mb-6">Create New Challenge</h1>
        <CreateChallengeForm />
      </div>
    </RouteGuard>
  );
} 