import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { adminAuth } from './admin-auth.js';
import type { Env } from '../index.js';

const mocks = vi.hoisted(() => ({
  sessionRows: 0,
  member: null as null | Record<string, unknown>,
}));

vi.mock('@line-crm/db', () => ({
  ADMIN_SESSION_TOKEN_PREFIX: 'lhs_',
  normalizeEmail: (value: string) => value.trim().toLowerCase() || null,
  getStaffByEmail: vi.fn(async () => mocks.member),
  verifyPassword: vi.fn(
    async (password: string, stored: string) =>
      password === 'correct-password' && stored === 'hash',
  ),
  createAdminSession: vi.fn(async () => {
    mocks.sessionRows += 1;
    return {
      token: `lhs_${'a'.repeat(64)}`,
      id: 'session',
      expiresAt: '2099-01-01',
    };
  }),
  deleteAdminSession: vi.fn(async () => {
    mocks.sessionRows -= 1;
  }),
  deleteAdminSessionsForStaff: vi.fn(),
  getStaffById: vi.fn(),
  hashPassword: vi.fn(),
  setStaffPassword: vi.fn(),
  validatePasswordStrength: vi.fn(),
}));

vi.mock('../middleware/auth.js', async (original) => {
  const actual = await original<typeof import('../middleware/auth.js')>();
  return {
    ...actual,
    authenticateApiToken: vi.fn(
      async (c: { env: { API_KEY: string } }, token: string) => {
        if (token === c.env.API_KEY) {
          return { id: 'env-owner', name: 'Owner', role: 'owner' };
        }
        if (token === 'staff-key') {
          return { id: 'staff-1', name: 'Staff', role: 'staff' };
        }
        return null;
      },
    ),
  };
});

function app() {
  const instance = new Hono<Env>();
  instance.route('/', adminAuth);
  return instance;
}

const env = {
  DB: {} as D1Database,
  API_KEY: 'env-key',
  ADMIN_ORIGIN: 'https://admin.example.com',
  WORKER_URL: 'https://api.example.com',
} as Env['Bindings'];

beforeEach(() => {
  mocks.sessionRows = 0;
  mocks.member = {
    id: 'staff-1',
    name: 'Staff',
    role: 'staff',
    password_hash: 'hash',
  };
});

describe('admin auth', () => {
  it('logs in with email/password and sets an lhs cookie', async () => {
    const res = await app().request(
      '/api/auth/login',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'STAFF@example.com',
          password: 'correct-password',
        }),
      },
      env,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toContain('lh_admin_session=lhs_');
  });

  it('uses the same message for every invalid password login', async () => {
    const invalidMembers = [
      { ...mocks.member, password_hash: 'hash' },
      null,
      { ...mocks.member, password_hash: null },
      null,
    ];

    for (const member of invalidMembers) {
      mocks.member = member;
      const res = await app().request(
        '/api/auth/login',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'cf-connecting-ip': crypto.randomUUID(),
          },
          body: JSON.stringify({
            email: `${crypto.randomUUID()}@example.com`,
            password: 'wrong-password',
          }),
        },
        env,
      );

      expect(res.status).toBe(401);
      expect((await res.json() as { error: string }).error).toBe(
        'メールアドレスまたはパスワードが正しくありません',
      );
    }
  });

  it('keeps env API key in its cookie', async () => {
    const res = await app().request(
      '/api/auth/login',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: 'env-key' }),
      },
      env,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toContain('lh_admin_session=env-key');
  });

  it('converts a staff API key to an lhs session', async () => {
    const res = await app().request(
      '/api/auth/login',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: 'staff-key' }),
      },
      env,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toContain('lh_admin_session=lhs_');
  });

  it('deletes the session on logout', async () => {
    mocks.sessionRows = 1;
    const res = await app().request(
      '/api/auth/logout',
      {
        method: 'POST',
        headers: {
          Cookie: `lh_admin_session=lhs_${'a'.repeat(64)}`,
        },
      },
      env,
    );

    expect(res.status).toBe(200);
    expect(mocks.sessionRows).toBe(0);
  });

  it('rate limits the eleventh password attempt', async () => {
    let status = 0;
    const ip = crypto.randomUUID();

    for (let attempt = 0; attempt < 11; attempt += 1) {
      mocks.member = null;
      const res = await app().request(
        '/api/auth/login',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'cf-connecting-ip': ip,
          },
          body: JSON.stringify({
            email: `limit-${crypto.randomUUID()}@example.com`,
            password: 'wrong-password',
          }),
        },
        env,
      );
      status = res.status;
    }

    expect(status).toBe(429);
  });
});
