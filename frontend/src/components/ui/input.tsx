import * as React from "react";
import { cn } from "@/lib/utils";

const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type, value, defaultValue, ...props }, ref) => {
    // Determine if this should be a controlled component based on if value is explicitly provided
    const isControlled = value !== undefined;
    
    // Ensure we're consistently using either controlled or uncontrolled approach
    const inputProps = isControlled 
      ? { value } // Controlled input
      : { defaultValue }; // Uncontrolled input
    
    return (
      <input
        type={type}
        className={cn(
          "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
          className
        )}
        ref={ref}
        {...inputProps}
        {...props}
      />
    );
  }
);
Input.displayName = "Input";

export { Input };