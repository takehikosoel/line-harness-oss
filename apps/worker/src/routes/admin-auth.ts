import { Hono } from 'hono';
import type { Env } from '../index.js';
import {
  ADMIN_AUTH_COOKIE,
  CSRF_COOKIE,
  adminSessionCookie,
  authenticateApiToken,
  cookieToken,
  csrfCookie,
  csrfTokenFromCookie,
  expiredCookie,
} from '../middleware/auth.js';
import { resolveAdminAuthConfig } from '../middleware/admin-auth-config.js';
import {
  ADMIN_SESSION_TOKEN_PREFIX,
  createAdminSession,
  deleteAdminSession,
  deleteAdminSessionsForStaff,
  getStaffByEmail,
  getStaffById,
  hashPassword,
  normalizeEmail,
  setStaffPassword,
  validatePasswordStrength,
  verifyPassword,
} from '@line-crm/db';
import { checkLoginAttempt, getClientIp } from '../middleware/rate-limit.js';

export const adminAuth = new Hono<Env>();

/**
 * POST /api/auth/login
 *
 * Validates the API key, then issues:
 *   - lh_admin_session (HttpOnly) — the credential, never exposed to JS.
 *   - lh_csrf (readable) — the double-submit CSRF token, also returned in the
 *     body so a cross-site SPA (which cannot read the API's cookie) can echo it
 *     back via the X-CSRF-Token header.
 *
 * Refuses with a clear error when the topology cannot deliver the cookie,
 * turning the silent "login breaks after deploy" failure into an actionable
 * configuration error.
 */
adminAuth.post('/api/auth/login', async (c) => {
  const config = resolveAdminAuthConfig(c.env, { requestOrigin: new URL(c.req.url).origin });
  if (config.misconfigured) {
    console.error('[admin-auth] refused login — misconfigured topology:', config.misconfigured);
    return c.json({ success: false, error: config.misconfigured }, 500);
  }

  const body = await c.req
    .json<{ email?: string; password?: string; apiKey?: string }>()
    .catch(() => ({} as { email?: string; password?: string; apiKey?: string }));
  if (body.email && body.password) {
    const normalizedEmail = normalizeEmail(body.email);
    if (!normalizedEmail) return c.json({ success: false, error: 'Invalid request' }, 400);
    const ipLimit = checkLoginAttempt(`login:ip:${getClientIp(c)}`);
    const emailLimit = checkLoginAttempt(`login:email:${normalizedEmail}`);
    if (!ipLimit.ok || !emailLimit.ok) {
      return c.json(
        { success: false, error: 'Too many requests. Please try again later.' },
        { status: 429, headers: { 'Retry-After': String(Math.max(ipLimit.retryAfter, emailLimit.retryAfter)) } },
      );
    }
    const member = await getStaffByEmail(c.env.DB, normalizedEmail);
    // 存在しないメールでも PBKDF2 を一度実行し、応答時間から登録有無を推測されにくくする。
    const dummy = 'pbkdf2$sha256$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    const valid = await verifyPassword(body.password, member?.password_hash ?? dummy);
    if (!member?.password_hash || !valid) {
      return c.json({ success: false, error: 'メールアドレスまたはパスワードが正しくありません' }, 401);
    }
    const session = await createAdminSession(c.env.DB, member.id, { userAgent: c.req.header('User-Agent') });
    const csrfToken = crypto.randomUUID();
    c.header('Set-Cookie', adminSessionCookie(session.token, config.sameSite), { append: true });
    c.header('Set-Cookie', csrfCookie(csrfToken, config.sameSite), { append: true });
    return c.json({ success: true, data: { id: member.id, name: member.name, role: member.role }, csrfToken });
  }
  const apiKey = body.apiKey?.trim() ?? '';
  if (!apiKey) return c.json({ success: false, error: 'Invalid request' }, 400);
  const staff = await authenticateApiToken(c, apiKey || null);

  if (!staff) {
    return c.json({ success: false, error: 'Unauthorized' }, 401);
  }

  const csrfToken = crypto.randomUUID();
  // env-owner は staff_members 行がなく FK を張れないため、従来どおり API キーを Cookie に入れる。
  const cookieCredential = staff.id === 'env-owner'
    ? apiKey
    : (await createAdminSession(c.env.DB, staff.id, { userAgent: c.req.header('User-Agent') })).token;
  c.header('Set-Cookie', adminSessionCookie(cookieCredential, config.sameSite), { append: true });
  c.header('Set-Cookie', csrfCookie(csrfToken, config.sameSite), { append: true });
  return c.json({ success: true, data: staff, csrfToken });
});

/**
 * POST /api/auth/logout — clears both cookies. No CSRF required: clearing your
 * own session is not a meaningful CSRF target, and this keeps logout resilient
 * even if the CSRF token was lost client-side.
 */
adminAuth.post('/api/auth/logout', async (c) => {
  const { sameSite } = resolveAdminAuthConfig(c.env, { requestOrigin: new URL(c.req.url).origin });
  const token = cookieToken(c);
  if (token?.startsWith(ADMIN_SESSION_TOKEN_PREFIX)) {
    try { await deleteAdminSession(c.env.DB, token); } catch { /* ログアウトは常に成功させる */ }
  }
  c.header('Set-Cookie', expiredCookie(ADMIN_AUTH_COOKIE, sameSite), { append: true });
  c.header('Set-Cookie', expiredCookie(CSRF_COOKIE, sameSite), { append: true });
  return c.json({ success: true, data: null });
});

/**
 * GET /api/auth/session — returns the authenticated staff (set by the auth
 * middleware) plus the current CSRF token, refreshing the CSRF cookie if it is
 * missing (e.g. after a reload that dropped the in-memory token). This lets the
 * SPA recover the CSRF token without forcing a re-login.
 */
adminAuth.get('/api/auth/session', async (c) => {
  const config = resolveAdminAuthConfig(c.env, { requestOrigin: new URL(c.req.url).origin });
  let csrfToken = csrfTokenFromCookie(c);
  if (!csrfToken) {
    csrfToken = crypto.randomUUID();
    c.header('Set-Cookie', csrfCookie(csrfToken, config.sameSite), { append: true });
  }
  const current = c.get('staff');
  const member = current.id === 'env-owner' ? null : await getStaffById(c.env.DB, current.id);
  return c.json({ success: true, data: { ...current, hasPassword: Boolean(member?.password_hash) }, csrfToken });
});

adminAuth.post('/api/auth/password', async (c) => {
  const current = c.get('staff');
  if (current.id === 'env-owner') {
    return c.json({ success: false, error: '環境変数のオーナーはパスワードを設定できません。スタッフとして登録してください' }, 400);
  }
  const body = await c.req.json<{ currentPassword?: string; newPassword?: string }>().catch(() => ({} as { currentPassword?: string; newPassword?: string }));
  if (!body.newPassword) return c.json({ success: false, error: 'newPassword is required' }, 400);
  const weakness = validatePasswordStrength(body.newPassword);
  if (weakness) return c.json({ success: false, error: weakness }, 400);
  const member = await getStaffById(c.env.DB, current.id);
  if (!member) return c.json({ success: false, error: 'Staff member not found' }, 404);
  if (member.password_hash && (!body.currentPassword || !(await verifyPassword(body.currentPassword, member.password_hash)))) {
    return c.json({ success: false, error: '現在のパスワードが正しくありません' }, 401);
  }
  await setStaffPassword(c.env.DB, member.id, await hashPassword(body.newPassword));
  await deleteAdminSessionsForStaff(c.env.DB, member.id);
  const config = resolveAdminAuthConfig(c.env, { requestOrigin: new URL(c.req.url).origin });
  const session = await createAdminSession(c.env.DB, member.id, { userAgent: c.req.header('User-Agent') });
  c.header('Set-Cookie', adminSessionCookie(session.token, config.sameSite), { append: true });
  return c.json({ success: true, data: null });
});
