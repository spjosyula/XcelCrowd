"use client";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  className?: string;
  hasNextPage?: boolean;
}

export function Pagination({ 
  currentPage, 
  totalPages, 
  onPageChange,
  className,
  hasNextPage
}: PaginationProps) {
  if (totalPages <= 1) {
    return null;
  }
  
  // If hasNextPage is explicitly provided, use it; otherwise fall back to page comparison
  const isNextButtonDisabled = hasNextPage !== undefined 
    ? !hasNextPage 
    : currentPage === totalPages;
  
  return (
    <nav className={cn("flex justify-center items-center mt-8", className)}>
      <ul className="flex space-x-4">
        <li>
          <Button
            variant="outline"
            disabled={currentPage === 1}
            onClick={() => onPageChange(currentPage - 1)}
            aria-label="Previous page"
            size="sm"
          >
            Previous
          </Button>
        </li>
        
        <li>
          <Button
            variant="outline"
            disabled={isNextButtonDisabled}
            onClick={() => onPageChange(currentPage + 1)}
            aria-label="Next page"
            size="sm"
          >
            Next
          </Button>
        </li>
      </ul>
    </nav>
  );
} 