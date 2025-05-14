import React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const chipVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset",
  {
    variants: {
      color: {
        gray: "bg-gray-50 text-gray-700 ring-gray-600/20",
        red: "bg-red-50 text-red-700 ring-red-600/20",
        yellow: "bg-yellow-50 text-yellow-700 ring-yellow-600/20",
        green: "bg-green-50 text-green-700 ring-green-600/20",
        blue: "bg-blue-50 text-blue-700 ring-blue-600/20",
        indigo: "bg-indigo-50 text-indigo-700 ring-indigo-600/20",
        purple: "bg-purple-50 text-purple-700 ring-purple-600/20",
        pink: "bg-pink-50 text-pink-700 ring-pink-600/20",
      },
      size: {
        sm: "px-2 py-0.5 text-xs",
        md: "px-2.5 py-0.5 text-sm",
        lg: "px-3 py-1 text-sm",
      },
    },
    defaultVariants: {
      color: "gray",
      size: "md",
    },
  }
);

export interface ChipProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof chipVariants> {
  onDelete?: () => void;
}

export const Chip = React.forwardRef<HTMLSpanElement, ChipProps>(
  ({ className, color, size, onDelete, children, ...props }, ref) => {
    return (
      <span
        ref={ref}
        className={cn(chipVariants({ color, size }), className)}
        {...props}
      >
        {children}
        {onDelete && (
          <button
            type="button"
            onClick={onDelete}
            className="ml-1 -mr-1 h-3.5 w-3.5 rounded-full hover:bg-gray-300/20 inline-flex items-center justify-center"
            aria-hidden="true"
          >
            <span className="sr-only">Remove</span>
            <svg
              className="h-2.5 w-2.5"
              stroke="currentColor"
              fill="none"
              viewBox="0 0 8 8"
            >
              <path
                strokeLinecap="round"
                strokeWidth="1.5"
                d="M1 1l6 6m0-6L1 7"
              />
            </svg>
          </button>
        )}
      </span>
    );
  }
); 