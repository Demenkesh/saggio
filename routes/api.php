<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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
// refister
Route::post('register', [App\Http\Controllers\Api\AuthController::class, 'register']);
// login
Route::post('login', [App\Http\Controllers\Api\AuthController::class, 'login']);

// Send password reset email
Route::post('sendResetLinkEmail', [App\Http\Controllers\Api\AuthController::class, 'sendResetLinkEmail']);

// Handle password reset
Route::post('password/reset', [App\Http\Controllers\Api\AuthController::class, 'reset']);

Route::middleware(['auth:sanctum'])->group(function () {
    Route::post('logout', [App\Http\Controllers\Api\AuthController::class, 'logout']);
});

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
