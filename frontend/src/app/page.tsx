import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Container } from "@/components/ui/container";
import { Navbar } from "@/components/navbar";

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen">
      <Navbar />
      
      {/* Hero Section */}
      <header className="bg-gradient-to-r from-primary-50 via-white to-lavender-50 py-16">
        <Container className="flex flex-col items-center text-center">
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6">
            <span className="text-primary">Xcel</span>
            <span className="text-royal">Crowd</span>
          </h1>
          <p className="text-xl md:text-2xl text-gray-600 mb-10 max-w-3xl">
            Connect talented students with innovative companies for meaningful project opportunities
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <Button asChild size="lg" className="text-base">
              <Link href="/auth/student">Join as Student</Link>
            </Button>
            <Button asChild variant="royal" size="lg" className="text-base">
              <Link href="/auth/company">Join as Company</Link>
            </Button>
          </div>
        </Container>
      </header>

      {/* Features Section */}
      <section className="py-16 bg-white">
        <Container>
          <h2 className="text-3xl font-bold text-center mb-12">How It Works</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card>
              <CardHeader>
                <CardTitle>For Students</CardTitle>
              </CardHeader>
              <CardContent>
                <p>Access real-world projects, build your portfolio, and connect with top companies looking for talent.</p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="outline" className="w-full">
                  <Link href="/auth/student">Sign Up</Link>
                </Button>
              </CardFooter>
            </Card>
            
            <Card>
              <CardHeader>
                <CardTitle>For Companies</CardTitle>
              </CardHeader>
              <CardContent>
                <p>Find motivated students to help with your projects, discover new talent, and support education.</p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="outline" className="w-full">
                  <Link href="/auth/company">Get Started</Link>
                </Button>
              </CardFooter>
            </Card>
            
            <Card>
              <CardHeader>
                <CardTitle>How We Match</CardTitle>
              </CardHeader>
              <CardContent>
                <p>Our platform uses smart matching to connect students with projects that fit their skills and interests.</p>
              </CardContent>
              <CardFooter>
                <Button asChild variant="outline" className="w-full">
                  <Link href="/about">Learn More</Link>
                </Button>
              </CardFooter>
            </Card>
          </div>
        </Container>
      </section>

      {/* Call to Action */}
      <section className="py-16 bg-primary-50">
        <Container className="text-center">
          <h2 className="text-3xl font-bold mb-6">Ready to Get Started?</h2>
          <p className="text-lg mb-8 max-w-2xl mx-auto">Join our platform today and start connecting with opportunities that matter.</p>
          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <Button asChild size="lg">
              <Link href="/auth/student">Join as Student</Link>
            </Button>
            <Button asChild variant="royal" size="lg">
              <Link href="/auth/company">Join as Company</Link>
            </Button>
          </div>
        </Container>
      </section>
      
      {/* Footer */}
      <footer className="mt-auto py-8 bg-gray-100">
        <Container>
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="mb-4 md:mb-0">
              <p className="font-semibold text-lg">
                <span className="text-primary">Xcel</span>
                <span className="text-royal">Crowd</span>
              </p>
            </div>
            <div className="flex gap-8">
              <Link href="/about" className="text-gray-600 hover:text-gray-900">About</Link>
              <Link href="/privacy" className="text-gray-600 hover:text-gray-900">Privacy</Link>
              <Link href="/terms" className="text-gray-600 hover:text-gray-900">Terms</Link>
              <Link href="/contact" className="text-gray-600 hover:text-gray-900">Contact</Link>
            </div>
          </div>
          <div className="mt-6 text-center text-gray-500 text-sm">
            &copy; {new Date().getFullYear()} XcelCrowd. All rights reserved.
          </div>
        </Container>
      </footer>
    </div>
  );
}