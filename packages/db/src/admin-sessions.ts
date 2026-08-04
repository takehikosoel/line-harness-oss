import { jstNow, toJstString } from './utils.js';
import type { StaffMember } from './staff.js';

export const ADMIN_SESSION_TTL_SECONDS = 604800;
export const ADMIN_SESSION_TOKEN_PREFIX = 'lhs_';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function tokenHash(token: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))));
}

export async function createAdminSession(
  db: D1Database,
  staffId: string,
  opts?: { userAgent?: string | null; ttlSeconds?: number },
): Promise<{ token: string; id: string; expiresAt: string }> {
  const token = ADMIN_SESSION_TOKEN_PREFIX + hex(crypto.getRandomValues(new Uint8Array(32)));
  const id = crypto.randomUUID();
  const createdAt = jstNow();
  const expiresAt = toJstString(new Date(Date.now() + (opts?.ttlSeconds ?? ADMIN_SESSION_TTL_SECONDS) * 1000));
  await db.prepare(`INSERT INTO admin_sessions
    (id, token_hash, staff_id, created_at, expires_at, last_used_at, user_agent)
    VALUES (?, ?, ?, ?, ?, NULL, ?)`)
    .bind(id, await tokenHash(token), staffId, createdAt, expiresAt, opts?.userAgent ?? null).run();
  return { token, id, expiresAt };
}

export async function getStaffBySessionToken(db: D1Database, token: string): Promise<StaffMember | null> {
  if (!token.startsWith(ADMIN_SESSION_TOKEN_PREFIX)) return null;
  const hash = await tokenHash(token);
  const row = await db.prepare(`SELECT staff_members.*, admin_sessions.expires_at AS session_expires_at
    FROM admin_sessions JOIN staff_members ON staff_members.id = admin_sessions.staff_id
    WHERE admin_sessions.token_hash = ? AND staff_members.is_active = 1`)
    .bind(hash).first<StaffMember & { session_expires_at: string }>();
  if (!row || new Date(row.session_expires_at).getTime() <= Date.now()) return null;
  await db.prepare('UPDATE admin_sessions SET last_used_at = ? WHERE token_hash = ?').bind(jstNow(), hash).run();
  const { session_expires_at: _, ...staff } = row;
  return staff;
}

export async function deleteAdminSession(db: D1Database, token: string): Promise<void> {
  await db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').bind(await tokenHash(token)).run();
}

export async function deleteAdminSessionsForStaff(db: D1Database, staffId: string): Promise<void> {
  await db.prepare('DELETE FROM admin_sessions WHERE staff_id = ?').bind(staffId).run();
}

export async function purgeExpiredAdminSessions(db: D1Database): Promise<number> {
  const rows = await db.prepare('SELECT id, expires_at FROM admin_sessions').all<{ id: string; expires_at: string }>();
  const expired = rows.results.filter((row) => new Date(row.expires_at).getTime() <= Date.now());
  for (const row of expired) await db.prepare('DELETE FROM admin_sessions WHERE id = ?').bind(row.id).run();
  return expired.length;
}
