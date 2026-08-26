<?php

namespace App\Http\Controllers;

use App\Mail\VerificationEmail;
use App\Mail\WelcomeEmail;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use App\Mail\ResetPasswordEmail;
use App\Mail\ResetPasswordsuccess;

class UserController extends Controller
{
    public function signup(Request $request)
    {
        $data = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:10',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $validatedData = $data->validated();
        $verificationToken = (string) random_int(100000, 999999);

        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => Hash::make($validatedData['password']),
            'verificationToken' => $verificationToken,
            'verificationTokenExpiresAt' => Carbon::now()->addHours(24),
        ]);


        $request->session()->regenerate();
        Auth::login($user);

        try {
            Mail::to($user->email)->send(new VerificationEmail($verificationToken));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
        }

        return response()->json([
            'success' => true,
            'user' => $user->makeHidden([
                'password',
                'verificationToken',
                'verificationTokenExpiresAt',
                'resetPasswordToken',
                'resetPasswordExpiresAt',
            ]),
            'message' => 'User created successfully.',
        ], 201);
    }

    public function login(Request $request)
    {
        $data = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $validatedData = $data->validated();

        $user = User::where('email', $validatedData['email'])->first();

        if (!$user || !Hash::check($validatedData['password'], $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid credentials',
            ], 401);
        }

        if (!$user->isVerified) {
            return response()->json([
                'success' => false,
                'message' => 'Please verify your email first.',
            ], 400);
        }


        $request->session()->regenerate();
        Auth::login($user);
        $user->lastlogin = Carbon::now();
        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'Login successful.',
            'user' => $user->makeHidden([
                'password',
                'verificationToken',
                'verificationTokenExpiresAt',
                'resetPasswordToken',
                'resetPasswordExpiresAt',
            ]),
        ]);
    }

    public function verifyemail(Request $request)
    {
        $data = Validator::make($request->all(), [
            'code' => 'required|string',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $token = $data->validated()['code'];

        $user = User::where('verificationToken', $token)
            ->where('verificationTokenExpiresAt', '>=', now())
            ->first();

        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Invalid or expired token'], 400);
        }

        $user->isVerified = true;
        $user->verificationToken = null;
        $user->verificationTokenExpiresAt = null;
        $user->save();

        try {
            Mail::to($user->email)->send(new WelcomeEmail($user->name, $user->email));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
        }

        return response()->json([
            'success' => true,
            'user' => $user->makeHidden(['password', 'resetPasswordToken', 'resetPasswordExpiresAt']),
            'message' => 'Email verified successfully',
        ]);
    }

    public function logoutt(Request $request)
    {

        Auth::guard('web')->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['success' => true, 'message' => 'Logged out successfully']);
    }

    public function forogotpassword(Request $request)
    {
        $data = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $user = User::where('email', $data->validated()['email'])->first();

        if (!$user) {
            return response()->json([
                'success' => true,
                'message' => 'If this email exists, a reset link has been sent.',
            ]);
        }

        $resettoken = bin2hex(random_bytes(32));
        $resettokenexpiresat = now()->addMinutes(15);
        $user->resetPasswordToken = hash('sha256', $resettoken);
        $user->resetPasswordExpiresAt = $resettokenexpiresat;
        $user->save();

        try {
            Mail::to($user->email)->send(new ResetPasswordEmail('http://localhost:5173/reset-password/' . $resettoken));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Reset password email failed to send.',
            ], 500);
        }

        return response()->json([
            'success' => true,
            'message' => 'If this email exists, a reset link has been sent.',
        ]);
    }

    public function resetpassword(Request $request, $passtoken)
    {
        $data = Validator::make($request->all(), [
            'password' => 'required|min:10',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $hashedIncomingToken = hash('sha256', $passtoken);

        $user = User::where('resetPasswordToken', $hashedIncomingToken)
            ->where('resetPasswordExpiresAt', '>', now())
            ->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired token',
            ], 400);
        }

        $user->password = Hash::make($data->validated()['password']);
        $user->resetPasswordToken = null;
        $user->resetPasswordExpiresAt = null;
        $user->save();

        
       /* if (config('session.driver') === 'database') {
            DB::table(config('session.table', 'sessions'))
                ->where('user_id', $user->id)
                ->delete();
        }*/

        try {
            Mail::to($user->email)->send(new ResetPasswordsuccess());
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
        }

        return response()->json([
            'success' => true,
            'message' => 'Password reset successfully',
        ]);
    }

  

    public function ResendverifyEmail(Request $request)
    {
        $data = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);

        if ($data->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => $data->errors(),
            ], 422);
        }

        $user = User::where('email', $data->validated()['email'])->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found',
            ], 404);
        }

        if ($user->isVerified) {
            return response()->json([
                'success' => false,
                'message' => 'Your email is already verified',
            ], 400);
        }

        $verificationToken = (string) random_int(100000, 999999);
        $user->verificationToken = $verificationToken;
        $user->verificationTokenExpiresAt = Carbon::now()->addHours(24);
        $user->save();

        try {
            Mail::to($user->email)->send(new VerificationEmail($verificationToken));
        } catch (\Exception $e) {
            Log::error('Email sending failed: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Failed to send verification email.',
            ], 500);
        }

        return response()->json([
            'success' => true,
            'message' => 'Verification email sent successfully',
        ]);
    }
}