import { NextResponse } from 'next/server';
import { AUTH_COOKIE_NAME, buildAuthToken, getPanelAuthUsername, isPanelAuthEnabled, verifyPanelCredentials } from '../../../../lib/auth';

export async function POST(request) {
  const formData = await request.formData();
  const username = String(formData.get('username') || '');
  const password = String(formData.get('password') || '');

  if (!isPanelAuthEnabled()) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  if (!verifyPanelCredentials(username, password)) {
    return NextResponse.redirect(new URL('/?authError=1', request.url));
  }

  const response = NextResponse.redirect(new URL('/', request.url));
  response.cookies.set({
    name: AUTH_COOKIE_NAME,
    value: buildAuthToken(getPanelAuthUsername()),
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 12
  });
  return response;
}
