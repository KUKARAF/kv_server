-- Migration: Add 'approval' type to api_keys for the KV Approver Android app.
-- Follows the same table-recreation pattern (SQLite can't ALTER CHECK).

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

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status   ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner    ON api_keys(owner_id);

-- Recreate dependent tables with correct FK references
CREATE TABLE approval_requests_new (
    id             TEXT NOT NULL PRIMARY KEY,
    api_key_id     TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    emoji_sequence TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','approved','rejected','expired')),
    requested_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at     TEXT NOT NULL
);
INSERT INTO approval_requests_new SELECT * FROM approval_requests;
DROP TABLE approval_requests;
ALTER TABLE approval_requests_new RENAME TO approval_requests;

CREATE TABLE api_key_scopes_new (
    id          TEXT NOT NULL PRIMARY KEY,
    api_key_id  TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    scope       TEXT NOT NULL,
    ops         TEXT NOT NULL,
    deny        INTEGER NOT NULL DEFAULT 0
);
INSERT INTO api_key_scopes_new SELECT * FROM api_key_scopes;
DROP TABLE api_key_scopes;
ALTER TABLE api_key_scopes_new RENAME TO api_key_scopes;

PRAGMA foreign_keys = ON;
