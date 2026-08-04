import { beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAdminSession, deleteAdminSession, deleteAdminSessionsForStaff, getStaffBySessionToken, purgeExpiredAdminSessions } from '../src/admin-sessions.js';

let sqlite: Database.Database; let db: D1Database;
function d1(s: Database.Database): D1Database { return { prepare(q:string) { const stmt=s.prepare(q); return { bind(...p:unknown[]) { return { async run(){const x=stmt.run(...p);return {meta:{changes:x.changes}}}, async first<T>(){return (stmt.get(...p) as T)??null}, async all<T>(){return {results:stmt.all(...p) as T[]}} } }, async all<T>(){return {results:stmt.all() as T[]}} }; } } as unknown as D1Database }
beforeEach(() => { sqlite=new Database(':memory:'); sqlite.exec(readFileSync(join(dirname(fileURLToPath(import.meta.url)),'..','schema.sql'),'utf8')); sqlite.prepare("INSERT INTO staff_members (id,name,email,role,api_key) VALUES ('s','Staff','s@example.com','staff','lh_s')").run(); db=d1(sqlite) });
describe('admin sessions', () => {
  it('creates, resolves, and stores only a hash', async () => { const x=await createAdminSession(db,'s'); expect((await getStaffBySessionToken(db,x.token))?.id).toBe('s'); const row=sqlite.prepare('SELECT token_hash FROM admin_sessions').get() as {token_hash:string}; expect(row.token_hash).not.toContain(x.token); await deleteAdminSession(db,x.token); expect(await getStaffBySessionToken(db,x.token)).toBeNull() });
  it('rejects expired and inactive staff', async () => { const x=await createAdminSession(db,'s',{ttlSeconds:-1}); expect(await getStaffBySessionToken(db,x.token)).toBeNull(); const y=await createAdminSession(db,'s'); sqlite.prepare("UPDATE staff_members SET is_active=0 WHERE id='s'").run(); expect(await getStaffBySessionToken(db,y.token)).toBeNull() });
  it('deletes by staff and purges expired rows', async () => { await createAdminSession(db,'s'); await deleteAdminSessionsForStaff(db,'s'); expect((sqlite.prepare('SELECT count(*) n FROM admin_sessions').get() as {n:number}).n).toBe(0); await createAdminSession(db,'s',{ttlSeconds:-1}); expect(await purgeExpiredAdminSessions(db)).toBe(1) });
});
