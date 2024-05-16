<?php

namespace App\Http\Controllers;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use App\Models\User; 
use App\Models\Log; 
use App\Jobs\SendVerificationEmailJob;

class AuthController extends Controller
{

    protected $limiter;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    public function register(Request $request)
    {
        // Check if the email already exists
        $existingUser = User::where('email', $request->email)->first();
        if ($existingUser) {
            return response()->json(['error' => 'Email is already registered'], 422);
        }

        // Rate limit the register API
        $this->ensureRegisterAttemptsAreNotExceeded($request);

        // Validate request data
        $request->validate([
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
        ]);

        // Create user
        $user = User::create([
            'email' => $request->email,
            'password' => Hash::make($request->password), 
            'verification_code' => rand(100000, 999999),
        ]);

        $user->save();

        // Dispatch job to send verification email after one minute
        SendVerificationEmailJob::dispatch($user)->delay(now()->addMinutes(1));

        // Log the event
        Log::create([
            'user_id' => $user->id,
            'action' => 'register',
        ]);

        return response()->json(['message' => 'User registered successfully'], 201);
    }

    protected function ensureRegisterAttemptsAreNotExceeded(Request $request)
    {
        if ($this->limiter->tooManyAttempts($this->registerThrottleKey($request), 1)) {
            return response()->json(['error' => 'Too many registration attempts. Please try again later.'], 429);
        }
    }

    protected function registerThrottleKey(Request $request)
    {
        return 'register|' . mb_strtolower($request->input('email')) . '|' . $request->ip();
    }

    public function verify(Request $request)
{
    // Validate request data
    $request->validate([
        'email' => 'required|email',
        'verification_code' => 'required',
    ]);

    // Find user by email
    $user = User::where('email', $request->email)->first();

    if (!$user) {
        return response()->json(['error' => 'Incorrect username'], 422);
    }

    // Check if the verification code matches
    if ($user->verification_code !== $request->verification_code) {
        return response()->json(['error' => 'Incorrect verification code'], 422);
    }

    // Activate user account
    $user->update(['verified' => true]);

    // Log the event
    Log::create([
        'user_id' => $user->id,
        'action' => 'verify',
    ]);

    return response()->json(['message' => 'User account verified successfully']);
}


    public function login(Request $request)
    {
        $this->ensureLoginAttemptsAreNotExceeded($request);

        // Validate request data
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return response()->json(['error' => 'Unregistered email'], 401);
        }

        // Authenticate user
        if (!auth()->attempt($request->only('email', 'password'))) {
            $this->incrementLoginAttempts($request);
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Clear login attempts since login was successful
        $this->limiter->clear($this->throttleKey($request));

        // Log the event
        Log::create([
            'user_id' => auth()->user()->id,
            'action' => 'login',
        ]);

        return response()->json(['message' => 'Login successful', 'user' => auth()->user()]);
    }

    protected function ensureLoginAttemptsAreNotExceeded(Request $request)
    {
        if ($this->limiter->tooManyAttempts($this->throttleKey($request), 2)) {
            return response()->json(['error' => 'Too many login attempts. Please try again later.'], 429);
        }
    }


    protected function incrementLoginAttempts(Request $request)
    {
        $this->limiter->hit($this->throttleKey($request));
    }

    protected function throttleKey(Request $request)
    {
        return 'login|' . mb_strtolower($request->input('email')).'|'.$request->ip();
    }

}
