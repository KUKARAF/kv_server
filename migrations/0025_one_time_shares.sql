CREATE TABLE one_time_shares (
    id          TEXT PRIMARY KEY,
    owner_id    TEXT NOT NULL,
    kv_key      TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT
);

CREATE INDEX idx_ots_expires ON one_time_shares(expires_at)
    WHERE expires_at IS NOT NULL;
