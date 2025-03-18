import React from "react";

export default function HomePage() {
  return (
    <div className="flex flex-col min-h-screen">

      <main className="flex-grow container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold mb-6">
            Welcome to XcelCrowd Landing Page
          </h1>
        </div>
      </main>
      
      <footer className="bg-gray-100 dark:bg-gray-900 py-6">
        <div className="container mx-auto px-4 text-center">
          <p>&copy; {new Date().getFullYear()} XcelCrowd. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
