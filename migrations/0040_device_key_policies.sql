-- Per-device KV key access policies + escalating temporary device bans.
--
-- Why: a device-bound session token (api_keys.type='session' with device_id, minted via
-- session_request approval — see 0038) is otherwise a full admin session for its owner, so a
-- compromised/misbehaving device could read every KV entry (i.e. every stored API key). These
-- tables let the owner restrict which KV entry *names* each device may read:
--   allow_all  — default / no row: unchanged behaviour (backwards compatible)
--   allow_list — only names in device_policy_keys
--   deny_list  — everything except names in device_policy_keys
--   regex      — names fully matching `pattern`
-- A device requesting a disallowed entry is treated as compromised: it gets a temporary ban
-- (DEVICE_BAN_BASE_SECS * 2^(n-1), capped at 30 days) during which every device-attributable
-- request is rejected. ban_count survives unbans/expiry so repeat offences escalate.
--
-- Attribution: a device-bound session (and every credential that session mints) carries the
-- device in api_keys.device_id (0038), so the device's ban and policy apply to all of them.
--
-- Rows are removed with their device (ON DELETE CASCADE, foreign_keys is enabled on the pool;
-- devices::handlers::delete also deletes them explicitly). api_keys.device_id (0038) has no ON
-- DELETE action, so device deletion explicitly DELETES the device's api_keys rows (+ their
-- dependents) in the same transaction — never NULLs them, which would turn a live device token
-- into an unrestricted non-device credential.

CREATE TABLE device_policies (
    device_id  TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    owner_id   TEXT NOT NULL,
    mode       TEXT NOT NULL CHECK (mode IN ('allow_all','allow_list','deny_list','regex')),
    pattern    TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE device_policy_keys (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kv_key    TEXT NOT NULL,
    PRIMARY KEY (device_id, kv_key)
);

CREATE TABLE device_bans (
    device_id     TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    owner_id      TEXT NOT NULL,
    banned_at     TEXT,          -- NULL = not currently banned (history kept via ban_count)
    unban_at      TEXT,
    ban_count     INTEGER NOT NULL DEFAULT 0,
    last_key      TEXT,          -- the offending KV entry name (name only, never a value)
    last_ip       TEXT
);

CREATE INDEX idx_device_policies_owner ON device_policies(owner_id);
CREATE INDEX idx_device_bans_owner ON device_bans(owner_id);
