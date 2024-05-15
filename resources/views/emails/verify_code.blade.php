<x-mail::message>
    # Verify Your Email Address

    Hello {{ $user->email }},

    Please use the following verification code to activate your account:

    Verification Code: {{ $user->verification_code }}

    Thanks for registering with us.

    {{-- Button --}}
    <x-mail::button :url="''">
        Verify Email
    </x-mail::button>
    <x-mail::button :url="url('/api/verify?email=' . urlencode($user->email) . '&verification_code=' . $user->verification_code)">
        Verify Email
    </x-mail::button>

    Regards,  
    {{ config('app.name') }}
</x-mail::message>
