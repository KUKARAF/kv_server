-- Proof-of-possession gate in front of session_requests creation. A caller who only knows
-- a device_id (not its private key) can request a challenge but can never produce the
-- correct nonce, so create_request (and therefore the admin's pending-approval screen)
-- is now unreachable without the device's private key.
CREATE TABLE IF NOT EXISTS session_request_challenges (
    id           TEXT NOT NULL PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id),
    nonce_hash   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'consumed')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_request_challenges_expires_at
    ON session_request_challenges(expires_at);
