import { NextResponse } from 'next/server';
import { AUTH_COOKIE_NAME, buildAuthToken, getPanelAuthUsername, isPanelAuthEnabled, verifyPanelCredentials } from '../../../lib/auth';

export const dynamic = 'force-dynamic';

export async function POST(request) {
  const formData = await request.formData();
  const username = String(formData.get('username') || '');
  const password = String(formData.get('password') || '');

  if (!isPanelAuthEnabled()) {
    return new NextResponse(null, {
      status: 303,
      headers: { Location: '/' }
    });
  }

  if (!verifyPanelCredentials(username, password)) {
    return new NextResponse(null, {
      status: 303,
      headers: { Location: '/?authError=1' }
    });
  }

  const response = new NextResponse(null, {
    status: 303,
    headers: { Location: '/' }
  });
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
