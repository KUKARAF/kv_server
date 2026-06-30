DROP TABLE IF EXISTS api_key_scopes;
ALTER TABLE kv_entries DROP COLUMN scope;
ALTER TABLE secret_requests DROP COLUMN scope;

CREATE TABLE api_key_allowed_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    kv_key     TEXT NOT NULL,
    UNIQUE(api_key_id, kv_key)
);
CREATE INDEX idx_api_key_allowed_keys_api_key_id ON api_key_allowed_keys(api_key_id);
