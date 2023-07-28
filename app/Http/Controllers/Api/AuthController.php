<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // register controller
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|max:191',
            'email' => 'required|email|unique:users,email|max:191',
            'password' => 'required|min:8',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'validation_error' => $validator->messages(),
            ]);
        } else {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            $token = $user->createToken($user->email . '_Token')->plainTextToken;

            return response()->json([
                'status' => Response::HTTP_OK, //200
                'username' => $user->name,
                'access_token' => $token,
                "message" => 'successfully registered user!',
            ], Response::HTTP_CREATED); //202
        }
    }

    // login controller
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|max:191',
            'password' => 'required|min:8',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'validation_error' => $validator->messages(),
            ]);
        } else {
            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'status' => Response::HTTP_UNAUTHORIZED, //401
                    'message' => 'Invalid credentials'
                ]);
            } else {
                $token = $user->createToken($user->email . '_Token')->plainTextToken;

                return response()->json([
                    'status' => Response::HTTP_OK, //200
                    'username' => $user->name,
                    'access_token' => $token,
                    "message" => 'successfully logged user!',
                ], Response::HTTP_ACCEPTED); //202
            }
        }
    }

    // logout controller
    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => Response::HTTP_OK,
            "message" => 'successfully logout user!',
        ], Response::HTTP_ACCEPTED);
    }



    public function sendResetLinkEmail(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $status = Password::sendResetLink($request->only('email'));

        if ($status === Password::RESET_LINK_SENT) {
            return response()->json([
                'message' => 'Password reset link sent successfully',
                'status' => Response::HTTP_OK,
            ]);
        } else {
            return response()->json([
                'message' => 'Unable to s
                end password reset link',
                'status' => Response::HTTP_INTERNAL_SERVER_ERROR, // 500
            ]);
        }
    }



    public function reset(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|confirmed|min:8',
        ]);

        $status = Password::reset($request->only('email', 'password', 'password_confirmation', 'token'), function ($user, $password) {
            $user->forceFill([
                'password' => bcrypt($password),
            ])->setRememberToken(Str::random(60));

            $user->save();
        });

        
        if ($status === Password::PASSWORD_RESET) {
            return response()->json([
                'message' => 'Password reset successfully', 'status' => Response::HTTP_OK
            ]);
        } else {
            return response()->json(['message' => 'Unable to reset password'], Response::HTTP_INTERNAL_SERVER_ERROR);

        }
    }
}
