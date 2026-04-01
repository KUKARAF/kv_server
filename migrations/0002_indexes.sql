CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash      ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status         ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_key_scopes_key_id   ON api_key_scopes(api_key_id);
CREATE INDEX IF NOT EXISTS idx_kv_entries_expires_at   ON kv_entries(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_session_tokens_hash     ON session_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_approval_requests_key   ON approval_requests(api_key_id, status);
