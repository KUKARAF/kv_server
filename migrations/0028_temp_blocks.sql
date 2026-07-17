-- Escalating temporary IP blocks. `unblock_at` = when an auto-block lifts;
-- NULL alongside a set `blocked_at` means a permanent block (grandfathers
-- existing rows and preserves a manual permanent-block escape hatch).
-- `block_count` tracks repeat offenses so durations escalate.
ALTER TABLE blocked_ips ADD COLUMN unblock_at TEXT;
ALTER TABLE blocked_ips ADD COLUMN block_count INTEGER NOT NULL DEFAULT 0;
