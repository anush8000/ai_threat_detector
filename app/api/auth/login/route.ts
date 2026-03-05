import { NextResponse } from 'next/server';

export async function POST(request: Request) {
    try {
        const { password } = await request.json();

        // Check against STEAMPIPE_PASSWORD to use as master app password
        const validPassword = process.env.STEAMPIPE_PASSWORD;

        if (!validPassword) {
            return NextResponse.json({ error: 'System not configured properly (missing password).' }, { status: 500 });
        }

        if (password === validPassword) {
            const response = NextResponse.json({ success: true });

            // Set secure HTTP-only cookie
            response.cookies.set({
                name: 'auth_token',
                value: 'authorized',
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 60 * 60 * 24 * 7, // 1 week
                path: '/',
            });

            return response;
        }

        return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    } catch {
        return NextResponse.json({ error: 'Invalid request' }, { status: 400 });
    }
}
