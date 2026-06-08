-- Extend secret_requests with optional key prefix and required key list.
ALTER TABLE secret_requests ADD COLUMN key_prefix    TEXT;
ALTER TABLE secret_requests ADD COLUMN required_keys TEXT; -- JSON array e.g. '["DATABASE_URL","SECRET_KEY"]'

-- Faux approvals: informational notices created when a recipient bypasses a required key.
-- Cascade-deleted when the parent secret_request is deleted.
CREATE TABLE faux_approvals (
    id                TEXT NOT NULL PRIMARY KEY,
    owner_id          TEXT NOT NULL,
    secret_request_id TEXT NOT NULL REFERENCES secret_requests(id) ON DELETE CASCADE,
    message           TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_faux_approvals_owner ON faux_approvals(owner_id);
