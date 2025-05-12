import Link from "next/link";
import { Container } from "@/components/ui/container";

export function Navbar() {
  return (
    <nav className="border-b py-4 bg-white">
      <Container>
        <div className="flex justify-between items-center">
          <Link href="/" className="font-bold text-2xl">
            <span className="text-primary">Xcel</span>
            <span className="text-royal">Crowd</span>
          </Link>
          <div className="hidden md:flex items-center gap-6">
            <Link href="/how-it-works" className="text-gray-600 hover:text-gray-900">
              How It Works
            </Link>
            <Link href="/for-students" className="text-gray-600 hover:text-gray-900">
              For Students
            </Link>
            <Link href="/for-companies" className="text-gray-600 hover:text-gray-900">
              For Companies
            </Link>
            <Link href="/about" className="text-gray-600 hover:text-gray-900">
              About
            </Link>
          </div>
        </div>
      </Container>
    </nav>
  );
} 