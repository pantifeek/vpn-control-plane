import { NextResponse } from 'next/server';
import { AUTH_COOKIE_NAME } from '../../../../lib/auth';

export async function POST(request) {
  const response = NextResponse.redirect(new URL('/', request.url));
  response.cookies.set({
    name: AUTH_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 0
  });
  return response;
}
