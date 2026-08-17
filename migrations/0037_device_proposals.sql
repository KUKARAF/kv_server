-- Self-service device enrollment: a headless client proposes itself (unauthenticated,
-- like session_requests) with a name + public key it generated locally. An admin reviews
-- the proposal and confirms via the existing WebAuthn-gated register_begin/register_finish
-- ceremony (see devices/handlers.rs) — that passkey touch remains the real security gate.
-- This table only removes the need for a human to manually copy/paste the public key and
-- the resulting device_id between a terminal and the browser.
CREATE TABLE IF NOT EXISTS device_proposals (
    id                   TEXT NOT NULL PRIMARY KEY,
    name                 TEXT NOT NULL,
    public_key           TEXT NOT NULL,
    key_type             TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending'
                              CHECK(status IN ('pending', 'confirmed', 'rejected', 'expired')),
    resulting_device_id  TEXT REFERENCES devices(id),
    poll_secret_hash     TEXT NOT NULL,
    requested_at         TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at           TEXT NOT NULL,
    confirmed_at         TEXT,
    confirmed_by         TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_proposals_status     ON device_proposals(status);
CREATE INDEX IF NOT EXISTS idx_device_proposals_expires_at ON device_proposals(expires_at);
