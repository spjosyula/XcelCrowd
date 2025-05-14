import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset",
  {
    variants: {
      variant: {
        default: "bg-gray-50 text-gray-700 ring-gray-700/10",
        primary: "bg-blue-50 text-blue-700 ring-blue-700/10",
        secondary: "bg-purple-50 text-purple-700 ring-purple-700/10",
        success: "bg-green-50 text-green-700 ring-green-700/10",
        warning: "bg-yellow-50 text-yellow-700 ring-yellow-700/10",
        danger: "bg-red-50 text-red-700 ring-red-700/10",
        info: "bg-indigo-50 text-indigo-700 ring-indigo-700/10",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
} 