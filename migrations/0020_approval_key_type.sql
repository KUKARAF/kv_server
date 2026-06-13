-- Add 'approval' type to api_keys so device tokens (KV Approver app) can be created.
-- SQLite can't ALTER a CHECK constraint, so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE api_keys_new (
    id           TEXT NOT NULL PRIMARY KEY,
    key_hash     TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('standard','one_time','approval_required','zero_trust','shareable','session','approval')),
    status       TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','pending_approval','used','revoked')),
    expires_at   TEXT,
    owner_id     TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

INSERT INTO api_keys_new SELECT * FROM api_keys;

DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status   ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner    ON api_keys(owner_id);

PRAGMA foreign_keys = ON;
