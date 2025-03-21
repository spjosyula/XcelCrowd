import Link from 'next/link';
import { Button } from '@/components/ui/button';

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6 bg-slate-50">
      <h1 className="text-4xl font-bold mb-8">XcelCrowd Platform</h1>
      <div className="flex flex-col space-y-4 max-w-md w-full">
        <Link href="/student/register" className="w-full">
          <Button className="w-full py-6 text-lg" variant="default">
            Student Registration
          </Button>
        </Link>
        <Link href="/company/register" className="w-full">
          <Button className="w-full py-6 text-lg" variant="default">
            Company Registration
          </Button>
        </Link>
        <Link href="/architect/register" className="w-full">
          <Button className="w-full py-6 text-lg" variant="default">
            Architect Registration
          </Button>
        </Link>
        <div className="mt-8 text-center">
          <p className="text-sm text-gray-500">Already have an account?</p>
          <div className="flex gap-4 justify-center mt-2">
            <Link href="/student/login" className="text-blue-500 hover:underline">Student Login</Link>
            <Link href="/company/login" className="text-blue-500 hover:underline">Company Login</Link>
            <Link href="/architect/login" className="text-blue-500 hover:underline">Architect Login</Link>
          </div>
        </div>
      </div>
    </main>
  );
}