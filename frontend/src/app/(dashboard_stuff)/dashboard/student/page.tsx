"use client";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Container } from "@/components/ui/container";
import { useRouter } from "next/navigation";

export default function StudentDashboardPage() {
  const router = useRouter();

  return (
    <Container>
      <div className="py-8">
        <h1 className="text-3xl font-bold mb-6">Student Dashboard</h1>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-4">Welcome to XcelCrowd</h2>
            <p className="text-gray-600 mb-6">
              Explore industry challenges and showcase your skills by submitting innovative solutions.
            </p>
            <Button 
              onClick={() => router.push("/challenge")}
              size="lg"
              className="w-full"
            >
              Solve Challenges
            </Button>
          </Card>
          
          <Card className="p-6">
            <h2 className="text-xl font-semibold mb-4">My Progress</h2>
            <div className="flex flex-col gap-2">
              <p className="text-gray-600">Challenges Submitted: 0</p>
              <p className="text-gray-600">Challenges In Progress: 0</p>
              <p className="text-gray-600">Challenges Approved: 0</p>
            </div>
          </Card>
        </div>
      </div>
    </Container>
  );
}