-- パスワードログイン用の情報を staff_members に追加する。
-- SQLite は ADD COLUMN IF NOT EXISTS を持たないため、再適用時の duplicate column は
-- 既存の手動適用・bootstrap 生成処理が安全なエラーとして扱う。
ALTER TABLE staff_members ADD COLUMN password_hash TEXT;
ALTER TABLE staff_members ADD COLUMN password_updated_at TEXT;

-- email をログイン ID として比較できる形へ統一する。空文字はログイン ID にならない。
UPDATE staff_members
SET email = NULLIF(lower(trim(email)), '')
WHERE email IS NOT NULL;

-- email は従来表示用途だけだったため、正規化後に重複した場合は最古の登録だけを残し、
-- 他を NULL にしても既存オペレーションを壊さない。created_at 同値は rowid 最小を残す。
UPDATE staff_members
SET email = NULL
WHERE email IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM staff_members older
    WHERE older.email = staff_members.email
      AND (older.created_at < staff_members.created_at
        OR (older.created_at = staff_members.created_at AND older.rowid < staff_members.rowid))
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_members_email_unique
  ON staff_members(email) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS admin_sessions (
  id           TEXT PRIMARY KEY,
  token_hash   TEXT NOT NULL UNIQUE,
  staff_id     TEXT NOT NULL REFERENCES staff_members(id) ON DELETE CASCADE,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  last_used_at TEXT,
  user_agent   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_sessions_token_hash ON admin_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_staff ON admin_sessions(staff_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);
