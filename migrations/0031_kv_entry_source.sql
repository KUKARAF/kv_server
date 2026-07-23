ALTER TABLE kv_entries ADD COLUMN source_management_key_id TEXT REFERENCES management_keys(id) ON DELETE SET NULL;
ALTER TABLE kv_entries ADD COLUMN source_provider_key_id TEXT;
