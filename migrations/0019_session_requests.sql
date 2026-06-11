CREATE TABLE IF NOT EXISTS session_requests (
    id              TEXT NOT NULL PRIMARY KEY,
    label           TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                         CHECK(status IN ('pending','approved','rejected','expired','delivered')),
    plaintext_token TEXT,
    session_key_id  TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
    approved_by     TEXT,
    requested_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    approved_at     TEXT,
    rejected_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_session_requests_status     ON session_requests(status);
CREATE INDEX IF NOT EXISTS idx_session_requests_expires_at ON session_requests(expires_at);
