CREATE TABLE IF NOT EXISTS blocked_ips (
    ip           TEXT NOT NULL PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    blocked_at   TEXT,
    last_failure TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_blocked
    ON blocked_ips(blocked_at) WHERE blocked_at IS NOT NULL;
