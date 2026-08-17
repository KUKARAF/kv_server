-- Nullable: only session tokens minted via session_request approval are device-bound.
-- Lets a device-bound session token answer "which device am I" (see admin whoami handler).
ALTER TABLE api_keys ADD COLUMN device_id TEXT REFERENCES devices(id);
CREATE INDEX IF NOT EXISTS idx_api_keys_device_id ON api_keys(device_id);
