<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use App\Http\Requests\LoginRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterRequest;

class AuthController extends Controller
{
    //user register
    public function register(RegisterRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('Testing')->accessToken;

        $user->scopes($request->scope);

        return response(['user' => $user, 'access_token' => $token]);
    }

    //user login
    public function login(LoginRequest $request)
    {
        $credentials = request(['email', 'password']);

        if (!Auth::attempt($credentials)) {
            return response(['message' => 'Unauthorized'], 401);
    }

        $user = Auth::user();

        $user->token() ? $user->token()->revoke() : '';

        $scopes = $this->getScope($user);

        $token = $user->createToken('Testing', json_decode($request->scope, true))->accessToken;

        return response()->json([
            'user' => $user,
            'scopes' => $scopes,
            'access_token' => $token
        ]);
    }

    //user get message with read scope
    public function getMessage()
    {
        if(checkScopes(Auth::user(), 'read'))
        {
            return response()->json(['message' => "Get Message"]);
        }

        return  response()->json(['message' => 'Unauthorized'], 403);
    }

    //user post message with write scope
    public function postMessage(Request $request)
    {
        if(checkScopes(Auth::user(), 'write'))
        {
            return response()->json(['message' => "Post Message"]);
        }

        return  response()->json(['message' => 'Unauthorized'], 403);

    }

    //user logout
    public function logout(Request $request)
    {
        $user = Auth::user();

        $user->token()->revoke();

        return response()->json(['message' => 'Successfully logged out'], 200);
    }

    //get user token's permission
    public function getScope($user)
    {
        $scopes = [];

        $accessToken = Passport::token()->where('user_id', $user->id)->first();

        if ($accessToken) {
            $scopes = Passport::token()->where('id', $accessToken->id)->first()->scopes;

            $scopes = $scopes;
        }

        return $scopes;
    }
}
