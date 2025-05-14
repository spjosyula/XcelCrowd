"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ChallengeDifficulty, ChallengeStatus } from "@/types/challenge";
import type { ChallengeFilters } from "@/types/challenge";

interface ChallengeFiltersProps {
  filters: ChallengeFilters;
  onFilterChange: (newFilters: ChallengeFilters) => void;
}

export function ChallengeFilters({ filters, onFilterChange }: ChallengeFiltersProps) {
  const [searchInput, setSearchInput] = useState(filters.searchTerm || "");
  
  // Handle search form submission
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    onFilterChange({ ...filters, searchTerm: searchInput, page: 1 });
  };
  
  // Handle status filter change
  const handleStatusChange = (status: string) => {
    onFilterChange({ 
      ...filters, 
      status: status === filters.status ? undefined : status,
      page: 1
    });
  };
  
  // Handle difficulty filter change
  const handleDifficultyChange = (difficulty: string) => {
    onFilterChange({ 
      ...filters, 
      difficulty: difficulty === filters.difficulty ? undefined : difficulty,
      page: 1
    });
  };
  
  // Clear all filters
  const handleClearFilters = () => {
    setSearchInput("");
    onFilterChange({
      page: 1,
      limit: filters.limit,
    });
  };
  
  return (
    <Card className="p-4">
      <form onSubmit={handleSearch} className="mb-4">
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="Search challenges..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="flex-1"
          />
          <Button type="submit">Search</Button>
        </div>
      </form>
      
      <div className="mb-4">
        <h3 className="text-sm font-semibold mb-2">Status</h3>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant={filters.status === "active" ? "default" : "outline"}
            onClick={() => handleStatusChange(ChallengeStatus.ACTIVE)}
          >
            Active
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.status === "closed" ? "default" : "outline"}
            onClick={() => handleStatusChange(ChallengeStatus.CLOSED)}
          >
            Closed
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.status === "completed" ? "default" : "outline"}
            onClick={() => handleStatusChange(ChallengeStatus.COMPLETED)}
          >
            Completed
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.status === "all" ? "default" : "outline"}
            onClick={() => handleStatusChange("all")}
          >
            All
          </Button>
        </div>
      </div>
      
      <div className="mb-4">
        <h3 className="text-sm font-semibold mb-2">Difficulty</h3>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant={filters.difficulty === ChallengeDifficulty.BEGINNER ? "default" : "outline"}
            onClick={() => handleDifficultyChange(ChallengeDifficulty.BEGINNER)}
          >
            Beginner
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.difficulty === ChallengeDifficulty.INTERMEDIATE ? "default" : "outline"}
            onClick={() => handleDifficultyChange(ChallengeDifficulty.INTERMEDIATE)}
          >
            Intermediate
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.difficulty === ChallengeDifficulty.ADVANCED ? "default" : "outline"}
            onClick={() => handleDifficultyChange(ChallengeDifficulty.ADVANCED)}
          >
            Advanced
          </Button>
          <Button
            type="button"
            size="sm"
            variant={filters.difficulty === ChallengeDifficulty.EXPERT ? "default" : "outline"}
            onClick={() => handleDifficultyChange(ChallengeDifficulty.EXPERT)}
          >
            Expert
          </Button>
        </div>
      </div>
      
      {(filters.status || filters.difficulty || filters.searchTerm) && (
        <Button 
          variant="outline" 
          onClick={handleClearFilters}
          className="w-full"
        >
          Clear Filters
        </Button>
      )}
    </Card>
  );
} 