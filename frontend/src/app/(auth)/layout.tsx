import React from 'react';
import { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Authentication | XcelCrowd',
  description: 'Student and company authentication for XcelCrowd platform',
};

export default function AuthLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className="min-h-screen bg-muted/40 flex flex-col">
      <header className="border-b bg-background h-16 flex items-center px-4 md:px-6">
        <div className="container flex items-center justify-between">
          <Link href="/" className="flex items-center space-x-2">
            <span className="font-bold text-xl">XcelCrowd</span>
          </Link>
        </div>
      </header>
      <main className="flex-1 flex items-center justify-center py-10 px-4 md:px-6">
        {children}
      </main>
      <footer className="border-t py-6 px-4 md:px-6">
        <div className="container flex flex-col items-center justify-center gap-4">
          <div className="text-center text-sm text-muted-foreground">
            &copy; {new Date().getFullYear()} XcelCrowd. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
