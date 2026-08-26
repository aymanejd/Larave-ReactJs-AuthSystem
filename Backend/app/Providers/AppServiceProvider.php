<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Mail;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {

        RateLimiter::for('signup', function ($request) {
            return Limit::perHour(5)->by($request->ip())
                ->response(function () {
                    return response()->json([
                        'success' => false,
                        'message' => 'Too many signup attempts. Please try again later',
                    ], 429);
                });
        });


        RateLimiter::for('login', function ($request) {
            $email = (string) $request->input('email');

            return [

                Limit::perMinute(5)->by('login-email:' . $email)
                    ->response(function () {
                        return response()->json([
                            'success' => false,
                            'message' => 'Too many login attempts for this account. Please try again later',
                        ], 429);
                    }),
                Limit::perMinute(10)->by('login-ip:' . $request->ip())
                    ->response(function () {
                        return response()->json([
                            'success' => false,
                            'message' => 'Too many login attempts from this device. Please try again later',
                        ], 429);
                    }),
            ];
        });


        RateLimiter::for('verify-email', function ($request) {
            return Limit::perMinute(6)->by($request->ip())
                ->response(function () {
                    return response()->json([
                        'success' => false,
                        'message' => 'Too many verification attempts. Please try again later',
                    ], 429);
                });
        });


        RateLimiter::for('resend-verify-email', function ($request) {
            $email = (string) $request->input('email');

            return [Limit::perMinutes(10, 3)->by('resend-verify:' . $email)
                ->response(function () {
                    return response()->json([
                        'success' => false,
                        'message' => 'Too many requests. Please wait before requesting another code',
                    ], 429);
                }), Limit::perMinutes(10, 10)->by('login-ip:' . $request->ip())
                ->response(function () {
                    return response()->json([
                        'success' => false,
                        'message' => 'Too many email request attempts from this device Please try again later',
                    ], 429);
                })];
        });


        RateLimiter::for('forgot-password', function ($request) {
            $email = (string) $request->input('email');

            return [
                Limit::perMinutes(10, 3)->by('forgot-email:' . $email)
                    ->response(function () {
                        return response()->json([
                            'success' => false,
                            'message' => 'Too many password reset requests for this email Please try again later.',
                        ], 429);
                    }),
                Limit::perMinutes(10, 8)->by('forgot-ip:' . $request->ip())
                    ->response(function () {
                        return response()->json([
                            'success' => false,
                            'message' => 'Too many password reset requests from this device Please try again later.',
                        ], 429);
                    }),
            ];
        });


        RateLimiter::for('reset-password', function ($request) {
            return Limit::perMinutes(10, 5)->by($request->ip())
                ->response(function () {
                    return response()->json([
                        'success' => false,
                        'message' => 'Too many attempts. Please try again later.',
                    ], 429);
                });
        });
    }
}