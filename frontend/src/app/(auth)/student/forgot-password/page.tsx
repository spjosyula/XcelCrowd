'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { requestPasswordResetSchema } from '@/lib/validations/auth';
import AuthCard from '@/components/ui/auth/AuthCard';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, CheckCircle2 } from 'lucide-react';
import authService from '@/services/auth.service';

type FormData = z.infer<typeof requestPasswordResetSchema>;

export default function ForgotPasswordPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitted, setIsSubmitted] = useState(false);

  const form = useForm<FormData>({
    resolver: zodResolver(requestPasswordResetSchema),
    defaultValues: {
      email: '',
    },
  });

  const onSubmit = async (data: FormData) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await authService.requestStudentPasswordReset(data);
      setIsSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (isSubmitted) {
    return (
      <div className="container py-8 md:py-12">
        <AuthCard title="Check Your Email">
          <div className="flex flex-col items-center justify-center py-6">
            <CheckCircle2 className="h-16 w-16 text-green-500 mb-4" />
            <h3 className="text-xl font-medium text-center mb-2">Reset Link Sent</h3>
            <p className="text-center text-muted-foreground mb-6">
              We've sent a password reset link to your email address. Please check your inbox and follow the instructions.
            </p>
            <Button className="w-full" asChild>
              <Link href="/student/login">
                Return to Login
              </Link>
            </Button>
          </div>
        </AuthCard>
      </div>
    );
  }

  return (
    <div className="container py-8 md:py-12">
      <AuthCard 
        title="Forgot Password" 
        description="Enter your email address and we'll send you a reset link"
      >
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>University Email</FormLabel>
                  <FormControl>
                    <Input 
                      type="email" 
                      placeholder="student@university.edu" 
                      {...field} 
                      disabled={isLoading} 
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Sending Reset Link...
                </>
              ) : (
                'Send Reset Link'
              )}
            </Button>
          </form>
        </Form>

        <div className="mt-4 text-center">
          <p className="text-sm text-gray-500">
            Remember your password?{' '}
            <Link href="/student/login" className="text-primary font-medium hover:underline">
              Back to Login
            </Link>
          </p>
        </div>
      </AuthCard>
    </div>
  );
} 