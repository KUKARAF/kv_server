-- Secret request links: one-time links for collecting secrets from external parties.
-- The owner creates a link, shares it, and the recipient submits key-value pairs.
-- The link becomes invalid after one use.

CREATE TABLE secret_requests (
    id           TEXT NOT NULL PRIMARY KEY,   -- UUID used in the /collect?id= link
    owner_id     TEXT NOT NULL,               -- OIDC subject of the creating admin
    owner_label  TEXT NOT NULL,               -- display name shown to submitter (email)
    description  TEXT,                        -- optional hint text shown on collect page
    scope        TEXT,                        -- optional scope assigned to submitted entries
    status       TEXT NOT NULL DEFAULT 'pending'
                     CHECK(status IN ('pending', 'fulfilled', 'revoked')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    fulfilled_at TEXT,
    expires_at   TEXT
);

CREATE INDEX idx_secret_requests_owner  ON secret_requests(owner_id);
CREATE INDEX idx_secret_requests_status ON secret_requests(status);
