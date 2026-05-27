CREATE TABLE IF NOT EXISTS device_auth_requests (
    id            TEXT NOT NULL PRIMARY KEY,
    label         TEXT,
    status        TEXT NOT NULL DEFAULT 'pending'
                       CHECK(status IN ('pending','approved','rejected','expired','delivered')),
    plaintext_key TEXT,
    api_key_id    TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
    approved_by   TEXT,
    requested_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL,
    approved_at   TEXT,
    rejected_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_auth_status     ON device_auth_requests(status);
CREATE INDEX IF NOT EXISTS idx_device_auth_expires_at ON device_auth_requests(expires_at);
