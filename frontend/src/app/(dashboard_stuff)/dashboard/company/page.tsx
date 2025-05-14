"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Container } from "@/components/ui/container";
import { RouteGuard } from "@/components/auth/RouteGuard";
import { UserRole } from "@/types/user";

export default function CompanyPage() {
  return (
    <RouteGuard roles={[UserRole.COMPANY]}>
      <CompanyDashboard />
    </RouteGuard>
  );
}

function CompanyDashboard() {
  const router = useRouter();

  const handleCreateChallenge = () => {
    // Note: This should eventually be a POST request to /challenge 
    // instead of a separate route, but we'll keep it for now
    router.push("/challenge/create");
  };

  return (
    <Container>
      <div className="py-8">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold">Company Dashboard</h1>
          <Button 
            onClick={handleCreateChallenge}
            variant="royal"
            className="flex items-center gap-2"
          >
            <span>Create Challenge</span>
          </Button>
        </div>
        {/* Add dashboard components here */}
      </div>
    </Container>
  );
}