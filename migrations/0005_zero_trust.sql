-- Zero Trust mode: client-side encryption via WebAuthn PRF extension.
-- The server stores only ciphertext and never sees plaintext.

PRAGMA foreign_keys = OFF;

-- Add 'zero_trust' to api_keys.type CHECK constraint (requires table recreation in SQLite).
CREATE TABLE api_keys_new (
    id           TEXT NOT NULL PRIMARY KEY,
    key_hash     TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('standard','one_time','approval_required','zero_trust')),
    status       TEXT NOT NULL DEFAULT 'active'
                     CHECK(status IN ('active','pending_approval','used','revoked')),
    expires_at   TEXT,
    owner_id     TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);
INSERT INTO api_keys_new (id, key_hash, label, type, status, expires_at, owner_id, created_at, last_used_at)
SELECT id, key_hash, label, type, status, expires_at, owner_id, created_at, last_used_at FROM api_keys;
DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash  ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status    ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner     ON api_keys(owner_id);

-- Add ZT columns to kv_entries (nullable; only populated for zero_trust entries).
-- All binary data is stored as base64url TEXT.
ALTER TABLE kv_entries ADD COLUMN zt_ciphertext   TEXT;
ALTER TABLE kv_entries ADD COLUMN zt_wrapped_dek  TEXT;
ALTER TABLE kv_entries ADD COLUMN zt_nonce        TEXT;
ALTER TABLE kv_entries ADD COLUMN zt_aad          TEXT;
ALTER TABLE kv_entries ADD COLUMN zt_credential_id TEXT;
ALTER TABLE kv_entries ADD COLUMN zt_prf_salt      TEXT;

-- WebAuthn credentials registered by each admin user.
-- public_key_cose stores the full serialized webauthn-rs Passkey JSON.
CREATE TABLE IF NOT EXISTS zero_trust_credentials (
    id              TEXT NOT NULL PRIMARY KEY,
    owner_id        TEXT NOT NULL,
    credential_id   TEXT NOT NULL UNIQUE,   -- base64url-encoded CredentialID
    public_key_cose TEXT NOT NULL,          -- JSON-serialized webauthn-rs Passkey
    device_label    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_zt_creds_owner ON zero_trust_credentials(owner_id);

-- Single-use ZT access token blocklist (jti of consumed tokens).
CREATE TABLE IF NOT EXISTS zt_used_tokens (
    jti        TEXT NOT NULL PRIMARY KEY,
    used_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zt_used_expires ON zt_used_tokens(expires_at);

PRAGMA foreign_keys = ON;
