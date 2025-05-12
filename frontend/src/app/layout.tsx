import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";
import { Toaster } from "react-hot-toast";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
});

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1.0,
};

export const metadata: Metadata = {
  title: "XcelCrowd",
  description: "A professional student-only networking and crowdsourcing platform",
  applicationName: "XcelCrowd",
  authors: [{ name: "XcelCrowd Team" }],
  keywords: ["students", "networking", "crowdsourcing", "professional", "collaboration"],
  robots: "index, follow",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} font-sans`}>
      <body className="min-h-screen bg-background font-sans antialiased text-foreground">
        {children}
        <Toaster position="top-right" />
      </body>
    </html>
  );
}