import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const migration = readFileSync(join(root, 'migrations/051_staff_password_and_sessions.sql'), 'utf8');
function apply(db: Database.Database) {
  for (const statement of migration.split(/;\s*(?:\r?\n|$)/).map(s => s.trim()).filter(Boolean)) {
    try { db.exec(statement); } catch (e) { if (!/duplicate column name|already exists/i.test(String(e))) throw e; }
  }
}

describe('049 migration', () => {
  it('normalizes duplicates, creates columns/tables, and is repeatable', () => {
    const db = new Database(':memory:');
    db.exec(`CREATE TABLE staff_members (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT, role TEXT NOT NULL, api_key TEXT UNIQUE NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      INSERT INTO staff_members VALUES ('a','A',' User@Example.com ','owner','lh_a',1,'2024-01-01','2024-01-01');
      INSERT INTO staff_members VALUES ('b','B','user@example.COM','staff','lh_b',1,'2024-02-01','2024-02-01');
      INSERT INTO staff_members VALUES ('c','C','  ','staff','lh_c',1,'2024-03-01','2024-03-01');`);
    apply(db); apply(db);
    expect(db.prepare('SELECT id,email FROM staff_members ORDER BY id').all()).toEqual([{ id:'a', email:'user@example.com' }, { id:'b', email:null }, { id:'c', email:null }]);
    expect(db.prepare("SELECT name FROM pragma_table_info('staff_members') WHERE name='password_hash'").get()).toBeTruthy();
    expect(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_sessions'").get()).toBeTruthy();
    expect(() => db.prepare("INSERT INTO staff_members (id,name,email,role,api_key,created_at,updated_at) VALUES ('d','D','user@example.com','staff','lh_d','x','x')").run()).toThrow();
    db.prepare("INSERT INTO staff_members (id,name,email,role,api_key,created_at,updated_at) VALUES ('d','D',NULL,'staff','lh_d','x','x')").run();
  });
});
