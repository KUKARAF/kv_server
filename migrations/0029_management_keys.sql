CREATE TABLE management_keys (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    provider     TEXT NOT NULL,
    label        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);
CREATE INDEX idx_management_keys_owner ON management_keys(owner_id);

CREATE TABLE management_key_bodies (
    management_key_id TEXT PRIMARY KEY REFERENCES management_keys(id) ON DELETE CASCADE,
    nonce      TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    aad        TEXT NOT NULL
);

CREATE TABLE management_key_recipients (
    id                 TEXT PRIMARY KEY,
    management_key_id  TEXT NOT NULL REFERENCES management_keys(id) ON DELETE CASCADE,
    device_id          TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_type           TEXT NOT NULL,
    ephemeral_pub      TEXT NOT NULL,
    dek_nonce          TEXT NOT NULL,
    encrypted_dek      TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_mgmt_key_recipients_device ON management_key_recipients(device_id, management_key_id);
CREATE INDEX idx_mgmt_key_recipients_key ON management_key_recipients(management_key_id);

CREATE TABLE provisioned_keys (
    id                 TEXT PRIMARY KEY,
    management_key_id  TEXT NOT NULL REFERENCES management_keys(id) ON DELETE CASCADE,
    provider           TEXT NOT NULL,
    provider_key_id    TEXT NOT NULL,
    label              TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at         TEXT
);
CREATE INDEX idx_provisioned_keys_mgmt_key ON provisioned_keys(management_key_id);

CREATE TABLE provisioned_key_bodies (
    provisioned_key_id TEXT PRIMARY KEY REFERENCES provisioned_keys(id) ON DELETE CASCADE,
    nonce      TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    aad        TEXT NOT NULL
);

CREATE TABLE provisioned_key_recipients (
    id                  TEXT PRIMARY KEY,
    provisioned_key_id  TEXT NOT NULL REFERENCES provisioned_keys(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_type            TEXT NOT NULL,
    ephemeral_pub       TEXT NOT NULL,
    dek_nonce           TEXT NOT NULL,
    encrypted_dek       TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_prov_key_recipients_device ON provisioned_key_recipients(device_id, provisioned_key_id);
CREATE INDEX idx_prov_key_recipients_key ON provisioned_key_recipients(provisioned_key_id);
