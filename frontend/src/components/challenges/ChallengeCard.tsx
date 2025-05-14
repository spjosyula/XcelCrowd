"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Challenge, ChallengeDifficulty, ChallengeStatus } from "@/types/challenge";
import { formatDate } from "@/lib/utils";
import { useRouter } from "next/navigation";

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

interface ChallengeCardProps {
  challenge: Challenge;
}

export function ChallengeCard({ challenge }: ChallengeCardProps) {
  const router = useRouter();
  
  // Format deadline
  const deadlineDate = new Date(challenge.deadline);
  const formattedDeadline = formatDate(deadlineDate);
  
  // Calculate if deadline is near (less than 7 days)
  const isDeadlineNear = deadlineDate.getTime() - Date.now() < 7 * 24 * 60 * 60 * 1000;
  
  return (
    <Card className="overflow-hidden hover:shadow-md transition-shadow duration-300">
      <div className="p-6">
        <div className="flex flex-wrap gap-2 mb-3">
          <Badge variant={getStatusVariant(challenge.status)}>
            {challenge.status.charAt(0).toUpperCase() + challenge.status.slice(1)}
          </Badge>
          <Badge variant={getDifficultyVariant(challenge.difficulty)}>
            {challenge.difficulty.charAt(0).toUpperCase() + challenge.difficulty.slice(1)}
          </Badge>
          {challenge.category.slice(0, 2).map((cat, index) => (
            <Badge key={index} variant="default">
              {cat}
            </Badge>
          ))}
        </div>
        
        <h3 className="text-xl font-semibold mb-2">{challenge.title}</h3>
        
        <p className="text-gray-600 mb-4 line-clamp-2">
          {challenge.description}
        </p>
        
        <div className="flex flex-col gap-1 mb-4 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500">Deadline:</span>
            <span className={`font-medium ${isDeadlineNear ? 'text-red-600' : ''}`}>
              {formattedDeadline}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Spots:</span>
            <span className="font-medium">
              {challenge.maxParticipants 
                ? `${challenge.currentParticipants}/${challenge.maxParticipants}`
                : 'Unlimited'}
            </span>
          </div>
        </div>
        
        <Button 
          onClick={() => router.push(`/challenge/${challenge._id}`)} 
          className="w-full"
        >
          View Challenge
        </Button>
      </div>
    </Card>
  );
} 