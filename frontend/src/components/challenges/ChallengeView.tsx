"use client";

import { formatDate } from "@/lib/date";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Chip } from "@/components/ui/chip";
import { Challenge, ChallengeDifficulty, ChallengeStatus, ChallengeVisibility } from "@/types/challenge";

interface ChallengeViewProps {
  challenge: Challenge;
  isPreview?: boolean;
}

export function ChallengeView({ challenge, isPreview = false }: ChallengeViewProps) {
  const getDifficultyColor = (difficulty: ChallengeDifficulty) => {
    switch (difficulty) {
      case ChallengeDifficulty.BEGINNER:
        return "bg-green-100 text-green-800";
      case ChallengeDifficulty.INTERMEDIATE:
        return "bg-blue-100 text-blue-800";
      case ChallengeDifficulty.ADVANCED:
        return "bg-purple-100 text-purple-800";
      case ChallengeDifficulty.EXPERT:
        return "bg-red-100 text-red-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusColor = (status: ChallengeStatus) => {
    switch (status) {
      case ChallengeStatus.DRAFT:
        return "bg-gray-100 text-gray-800";
      case ChallengeStatus.ACTIVE:
        return "bg-green-100 text-green-800";
      case ChallengeStatus.CLOSED:
        return "bg-orange-100 text-orange-800";
      case ChallengeStatus.COMPLETED:
        return "bg-blue-100 text-blue-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <Card className="p-6 mb-6">
      {isPreview && (
        <Badge variant="warning" className="mb-4 bg-yellow-50 text-yellow-800 border-yellow-200">
          Preview Mode
        </Badge>
      )}
      
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-2xl font-bold">{challenge.title}</h2>
          <div className="flex items-center mt-2 gap-2">
            <Badge className={getDifficultyColor(challenge.difficulty)}>
              {challenge.difficulty}
            </Badge>
            <Badge className={getStatusColor(challenge.status)}>
              {challenge.status}
            </Badge>
            {challenge.isCompanyVisible && challenge.company && (
              <span className="text-gray-600 text-sm">
                {typeof challenge.company === 'object' 
                  ? (challenge.company.name || challenge.company._id || 'Company Name')
                  : challenge.company}
              </span>
            )}
          </div>
        </div>
        <div className="text-right">
          <div className="text-gray-600 text-sm">
            {challenge.deadline ? (
              <>
                <span className="font-medium">Deadline:</span>{" "}
                {formatDate(new Date(challenge.deadline))}
              </>
            ) : null}
          </div>
          {challenge.maxParticipants && (
            <div className="text-gray-600 text-sm">
              <span className="font-medium">Participants:</span> Max {challenge.maxParticipants}
            </div>
          )}
        </div>
      </div>

      <div className="mb-6">
        <h3 className="text-lg font-medium mb-2">Description</h3>
        <div className="text-gray-700 whitespace-pre-line">{challenge.description}</div>
      </div>

      {challenge.requirements && challenge.requirements.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-2">Requirements</h3>
          <ul className="list-disc pl-5 space-y-1">
            {challenge.requirements.map((req, index) => (
              <li key={index} className="text-gray-700">{req}</li>
            ))}
          </ul>
        </div>
      )}

      {challenge.resources && challenge.resources.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-2">Resources</h3>
          <ul className="list-disc pl-5 space-y-1">
            {challenge.resources.map((resource, index) => (
              <li key={index} className="text-gray-700">
                {resource.startsWith('http') ? (
                  <a 
                    href={resource} 
                    target="_blank" 
                    rel="noopener noreferrer" 
                    className="text-blue-600 hover:underline"
                  >
                    {resource}
                  </a>
                ) : (
                  resource
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {challenge.rewards && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-2">Rewards</h3>
          <div className="text-gray-700 whitespace-pre-line">{challenge.rewards}</div>
        </div>
      )}

      {challenge.category && challenge.category.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-medium mb-2">Categories</h3>
          <div className="flex flex-wrap gap-2">
            {challenge.category.map((cat, index) => (
              <Chip key={index} color="blue">
                {cat}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {challenge.tags && challenge.tags.length > 0 && (
        <div className="mb-4">
          <h3 className="text-lg font-medium mb-2">Tags</h3>
          <div className="flex flex-wrap gap-2">
            {challenge.tags.map((tag, index) => (
              <Chip key={index} color="gray">
                {tag}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {challenge.visibility === ChallengeVisibility.PRIVATE && challenge.allowedInstitutions && challenge.allowedInstitutions.length > 0 && (
        <div className="mt-6">
          <h3 className="text-lg font-medium mb-2">Available To</h3>
          <div className="flex flex-wrap gap-2">
            {challenge.allowedInstitutions.map((institution, index) => (
              <Chip key={index} color="purple">
                {institution}
              </Chip>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
} 