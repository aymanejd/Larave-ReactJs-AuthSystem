<?php

use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Http\Controllers\CsrfCookieController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::post(
    '/signup',
    [UserController::class, 'signup']
)->middleware('throttle:signup');
Route::post(
    '/verify-email',
    [UserController::class, 'verifyemail']
)->middleware(['throttle:verify-email','auth:sanctum']);
Route::post(
    '/Resendverify-email',
    [UserController::class, 'ResendverifyEmail']
)->middleware(['throttle:resend-verify-email','auth:sanctum']);
Route::post('/login', [UserController::class, 'login'])->middleware('throttle:login')->name('login');
Route::middleware('auth:sanctum')->post('/logout', [UserController::class, 'logoutt']);

Route::post('/forgot-password', [UserController::class, 'forogotpassword'])->middleware('throttle:forgot-password');
Route::post('/reset-password/{passtoken}', [UserController::class, 'resetpassword'])->middleware('throttle:reset-password');
Route::middleware(['auth:sanctum','verified'] )->get('/auth-check', function (Request $request){
     return response()->json([
            'success' => true,
            'user' => $request->user(),
        ]);
});

Route::get('/sanctum/csrf-cookie', CsrfCookieController::class . '@show')->middleware('web');