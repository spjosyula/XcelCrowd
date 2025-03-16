import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground p-4">
      <div className="space-y-4 text-center">
        <h1 className="text-4xl font-bold">404</h1>
        <h2 className="text-2xl font-semibold">Page Not Found</h2>
        <p className="text-muted-foreground max-w-md mx-auto">
          The page you are looking for doesn&apos;t exist or has been moved.
        </p>
        <div className="pt-6">
          <Link 
            href="/"
            className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors 
            focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 
            disabled:opacity-50 disabled:pointer-events-none ring-offset-background 
            bg-primary text-primary-foreground hover:bg-primary/90 
            h-10 py-2 px-4"
          >
            Return to Home
          </Link>
        </div>
      </div>
    </div>
  );
}
