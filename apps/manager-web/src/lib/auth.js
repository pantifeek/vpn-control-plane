import crypto from 'node:crypto';

export const AUTH_COOKIE_NAME = 'vpn_panel_auth';

function getAuthSecret() {
  return process.env.PANEL_AUTH_SECRET || `${process.env.PANEL_AUTH_USERNAME || ''}:${process.env.PANEL_AUTH_PASSWORD || ''}`;
}

export function isPanelAuthEnabled() {
  return Boolean(process.env.PANEL_AUTH_USERNAME && process.env.PANEL_AUTH_PASSWORD);
}

export function getPanelAuthUsername() {
  return process.env.PANEL_AUTH_USERNAME || '';
}

export function buildAuthToken(username) {
  return crypto.createHmac('sha256', getAuthSecret()).update(String(username || '')).digest('hex');
}

export function verifyPanelCredentials(username, password) {
  if (!isPanelAuthEnabled()) return true;

  const expectedUsername = Buffer.from(process.env.PANEL_AUTH_USERNAME || '', 'utf8');
  const expectedPassword = Buffer.from(process.env.PANEL_AUTH_PASSWORD || '', 'utf8');
  const candidateUsername = Buffer.from(String(username || ''), 'utf8');
  const candidatePassword = Buffer.from(String(password || ''), 'utf8');

  return (
    expectedUsername.length === candidateUsername.length &&
    expectedPassword.length === candidatePassword.length &&
    crypto.timingSafeEqual(expectedUsername, candidateUsername) &&
    crypto.timingSafeEqual(expectedPassword, candidatePassword)
  );
}

export function verifyAuthCookie(cookieValue) {
  if (!isPanelAuthEnabled()) return true;
  if (!cookieValue) return false;
  return cookieValue === buildAuthToken(getPanelAuthUsername());
}
