import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
    // Only protect API routes
    if (request.nextUrl.pathname.startsWith('/api/') && !request.nextUrl.pathname.startsWith('/api/auth/')) {
        const authCookie = request.cookies.get('auth_token');

        // Check for a valid token
        if (!authCookie || authCookie.value !== 'authorized') {
            return NextResponse.json(
                { error: 'Unauthorized access. Please log in.' },
                { status: 401 }
            );
        }
    }

    // Protect the main dashboard route
    if (request.nextUrl.pathname === '/') {
        const authCookie = request.cookies.get('auth_token');

        // Redirect to login if not authenticated
        if (!authCookie || authCookie.value !== 'authorized') {
            return NextResponse.redirect(new URL('/login', request.url));
        }
    }

    return NextResponse.next();
}

export const config = {
    matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
