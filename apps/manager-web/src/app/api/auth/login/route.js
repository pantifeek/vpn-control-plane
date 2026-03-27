import { NextResponse } from 'next/server';
import { AUTH_COOKIE_NAME, buildAuthToken, getPanelAuthUsername, isPanelAuthEnabled, verifyPanelCredentials } from '../../../../lib/auth';

export async function POST(request) {
  const formData = await request.formData();
  const username = String(formData.get('username') || '');
  const password = String(formData.get('password') || '');
  const successUrl = request.nextUrl.clone();
  successUrl.pathname = '/';
  successUrl.search = '';
  const errorUrl = request.nextUrl.clone();
  errorUrl.pathname = '/';
  errorUrl.search = '?authError=1';

  if (!isPanelAuthEnabled()) {
    return NextResponse.redirect(successUrl);
  }

  if (!verifyPanelCredentials(username, password)) {
    return NextResponse.redirect(errorUrl);
  }

  const response = NextResponse.redirect(successUrl);
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
