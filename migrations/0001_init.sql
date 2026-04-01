CREATE TABLE IF NOT EXISTS kv_entries (
    key         TEXT    NOT NULL PRIMARY KEY,
    value       TEXT    NOT NULL,
    ttl_hours   REAL,
    ttl_sliding INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT,
    open_access INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT NOT NULL PRIMARY KEY,
    key_hash     TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('standard','one_time','approval_required')),
    status       TEXT NOT NULL DEFAULT 'active'
                      CHECK(status IN ('active','pending_approval','used','revoked')),
    expires_at   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS api_key_scopes (
    id          TEXT NOT NULL PRIMARY KEY,
    api_key_id  TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    key_pattern TEXT NOT NULL,
    ops         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id             TEXT NOT NULL PRIMARY KEY,
    api_key_id     TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    emoji_sequence TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','approved','rejected','expired')),
    requested_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_tokens (
    id           TEXT NOT NULL PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    oidc_subject TEXT NOT NULL,
    email        TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
