-- Add per-user ownership to kv_entries and api_keys.
-- kv_entries PK changes from (key) to (key, owner_id), so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE kv_entries_new (
    key         TEXT    NOT NULL,
    owner_id    TEXT    NOT NULL DEFAULT '',
    value       TEXT    NOT NULL,
    scope       TEXT,
    ttl_hours   REAL,
    ttl_sliding INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT,
    open_access INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (key, owner_id)
);

INSERT INTO kv_entries_new (key, owner_id, value, scope, ttl_hours, ttl_sliding, expires_at, open_access, created_at)
SELECT key, '', value, scope, ttl_hours, ttl_sliding, expires_at, open_access, created_at
FROM kv_entries;

DROP TABLE kv_entries;
ALTER TABLE kv_entries_new RENAME TO kv_entries;

CREATE INDEX IF NOT EXISTS idx_kv_entries_expires_at ON kv_entries(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_kv_entries_owner      ON kv_entries(owner_id);

ALTER TABLE api_keys ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_id);

PRAGMA foreign_keys = ON;
