-- Add 'shareable' key type for keys scoped to a single KV entry.
-- These keys can be used multiple times (unlike 'one_time' keys) and are ideal for shareable URLs.

-- Update the CHECK constraint on api_keys.type to include 'shareable'
CREATE TABLE api_keys_new (
    id           TEXT NOT NULL PRIMARY KEY,
    key_hash     TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('standard','one_time','approval_required','zero_trust','shareable')),
    status       TEXT NOT NULL DEFAULT 'active'
                      CHECK(status IN ('active','pending_approval','used','revoked')),
    expires_at   TEXT,
    owner_id     TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

INSERT INTO api_keys_new (id, key_hash, label, type, status, expires_at, owner_id, created_at, last_used_at)
SELECT id, key_hash, label, type, status, expires_at, owner_id, created_at, last_used_at
FROM api_keys;

DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;

-- Recreate foreign key constraints
CREATE TABLE approval_requests_new (
    id             TEXT NOT NULL PRIMARY KEY,
    api_key_id     TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    emoji_sequence TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','approved','rejected','expired')),
    requested_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at     TEXT NOT NULL
);

INSERT INTO approval_requests_new (id, api_key_id, emoji_sequence, status, requested_at, expires_at)
SELECT id, api_key_id, emoji_sequence, status, requested_at, expires_at
FROM approval_requests;

DROP TABLE approval_requests;
ALTER TABLE approval_requests_new RENAME TO approval_requests;

CREATE TABLE api_key_scopes_new (
    id          TEXT NOT NULL PRIMARY KEY,
    api_key_id  TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    scope       TEXT NOT NULL,
    ops         TEXT NOT NULL
);

INSERT INTO api_key_scopes_new (id, api_key_id, scope, ops)
SELECT id, api_key_id, scope, ops
FROM api_key_scopes;

DROP TABLE api_key_scopes;
ALTER TABLE api_key_scopes_new RENAME TO api_key_scopes;

CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_id);
