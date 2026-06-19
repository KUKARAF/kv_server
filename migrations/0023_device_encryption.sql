ALTER TABLE devices ADD COLUMN key_type TEXT NOT NULL DEFAULT 'p256';

ALTER TABLE kv_entries ADD COLUMN device_encrypted INTEGER NOT NULL DEFAULT 0;

CREATE TABLE device_kv_bodies (
    kv_key     TEXT NOT NULL,
    owner_id   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    aad        TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (kv_key, owner_id)
);

CREATE TABLE device_kv_recipients (
    id              TEXT PRIMARY KEY,
    kv_key          TEXT NOT NULL,
    owner_id        TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    key_type        TEXT NOT NULL,
    ephemeral_pub   TEXT NOT NULL,
    dek_nonce       TEXT NOT NULL,
    encrypted_dek   TEXT NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_dkv_recipients_device_key ON device_kv_recipients(device_id, kv_key, owner_id);
CREATE INDEX idx_dkv_recipients_key ON device_kv_recipients(kv_key, owner_id);
