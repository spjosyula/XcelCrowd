'use client';

import React, { useState } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { verifyEmailSchema } from '@/lib/validations/auth';
import AuthCard from '@/components/ui/auth/AuthCard';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, CheckCircle2 } from 'lucide-react';
import authService from '@/services/auth.service';

type FormData = z.infer<typeof verifyEmailSchema>;

export default function VerifyEmailPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isVerified, setIsVerified] = useState(false);

  const form = useForm<FormData>({
    resolver: zodResolver(verifyEmailSchema),
    defaultValues: {
      email: '',
      otp: '',
    },
  });

  const onSubmit = async (data: FormData) => {
    setIsLoading(true);
    setError(null);
    
    try {
      await authService.verifyStudentEmail(data);
      setIsVerified(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (isVerified) {
    return (
      <div className="container py-8 md:py-12">
        <AuthCard title="Email Verified">
          <div className="flex flex-col items-center justify-center py-6">
            <CheckCircle2 className="h-16 w-16 text-green-500 mb-4" />
            <h3 className="text-xl font-medium text-center mb-2">Email Successfully Verified</h3>
            <p className="text-center text-muted-foreground mb-6">
              Your email has been verified. You can now use all the features of your account.
            </p>
            <Button className="w-full" onClick={() => window.location.href = '/dashboard/student'}>
              Go to Dashboard
            </Button>
          </div>
        </AuthCard>
      </div>
    );
  }

  return (
    <div className="container py-8 md:py-12">
      <AuthCard 
        title="Verify Your Email" 
        description="Enter the verification code sent to your email"
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
                  <FormLabel>Email Address</FormLabel>
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

            <FormField
              control={form.control}
              name="otp"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Verification Code</FormLabel>
                  <FormControl>
                    <Input 
                      placeholder="123456" 
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
                  Verifying...
                </>
              ) : (
                'Verify Email'
              )}
            </Button>
          </form>
        </Form>

        <div className="mt-4 space-y-2">
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Didn't receive a code?{' '}
              <Button variant="link" className="p-0 h-auto font-normal" onClick={() => {}}>
                Resend Code
              </Button>
            </p>
          </div>
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Need help?{' '}
              <Button variant="link" className="p-0 h-auto font-normal" onClick={() => {}}>
                Contact Support
              </Button>
            </p>
          </div>
        </div>
      </AuthCard>
    </div>
  );
} 