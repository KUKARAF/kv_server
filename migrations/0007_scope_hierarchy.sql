-- Rename key_pattern to scope in api_key_scopes.
-- API key scopes now represent scope prefixes with "/" hierarchy:
-- a scope of "osmosis" covers entries with scope "osmosis", "osmosis/media", "osmosis/ai", etc.
ALTER TABLE api_key_scopes RENAME COLUMN key_pattern TO scope;
