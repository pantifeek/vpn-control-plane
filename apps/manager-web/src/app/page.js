import { cookies } from 'next/headers';
import Dashboard from '../components/dashboard';
import { AUTH_COOKIE_NAME, isPanelAuthEnabled, verifyAuthCookie } from '../lib/auth';

function LoginScreen({ hasError }) {
  return (
    <main style={{ maxWidth: 420, margin: '10vh auto', padding: 24 }}>
      <div style={{ background: '#fff', border: '1px solid #d8dde6', borderRadius: 16, padding: 24, boxShadow: '0 10px 30px rgba(15, 23, 42, 0.08)' }}>
        <h1 style={{ marginTop: 0, marginBottom: 8 }}>VPN Control Panel</h1>
        <p style={{ marginTop: 0, marginBottom: 20, color: '#5b6473' }}>Войдите, чтобы открыть панель управления.</p>
        {hasError && (
          <div style={{ marginBottom: 16, background: '#fff4f4', border: '1px solid #f2b8b5', color: '#8a1c1c', padding: 12, borderRadius: 10 }}>
            Неверный логин или пароль.
          </div>
        )}
        <form action="/auth/login" method="post" style={{ display: 'grid', gap: 12 }}>
          <input name="username" placeholder="Логин" autoComplete="username" style={{ padding: 12, borderRadius: 10, border: '1px solid #c8d0dc', fontSize: 16 }} />
          <input name="password" type="password" placeholder="Пароль" autoComplete="current-password" style={{ padding: 12, borderRadius: 10, border: '1px solid #c8d0dc', fontSize: 16 }} />
          <button type="submit" style={{ padding: 12, borderRadius: 10, border: '1px solid #111827', background: '#111827', color: '#fff', fontSize: 16 }}>
            Войти
          </button>
        </form>
      </div>
    </main>
  );
}

function AuthenticatedPage() {
  return (
    <>
      <div style={{ maxWidth: 1500, margin: '0 auto', padding: '18px 24px 0 24px', display: 'flex', justifyContent: 'flex-end' }}>
        <form action="/auth/logout" method="post">
          <button type="submit" style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid #c8d0dc', background: '#fff' }}>
            Выйти
          </button>
        </form>
      </div>
      <Dashboard />
    </>
  );
}

export default async function HomePage({ searchParams }) {
  const authEnabled = isPanelAuthEnabled();
  if (!authEnabled) {
    return <Dashboard />;
  }

  const cookieStore = await cookies();
  const isAuthenticated = verifyAuthCookie(cookieStore.get(AUTH_COOKIE_NAME)?.value);
  if (!isAuthenticated) {
    return <LoginScreen hasError={searchParams?.authError === '1'} />;
  }

  return <AuthenticatedPage />;
}
