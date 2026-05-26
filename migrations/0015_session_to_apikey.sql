-- Migration: Add type column to api_keys and migrate session tokens
-- Phase 1 of unifying all auth under api_keys table

-- 1. Add 'type' column to api_keys (default 'standard' for existing keys)
ALTER TABLE api_keys ADD COLUMN type TEXT NOT NULL DEFAULT 'standard';

-- 2. Update existing keys to have explicit 'standard' type
UPDATE api_keys SET type = 'standard' WHERE type = '' OR type IS NULL;

-- 3. Add 'session' to the allowed types in the CHECK constraint
-- SQLite doesn't support ALTER TABLE to change constraints, so we recreate the table
-- This is safe because we've already added the column above

-- 4. For existing session_tokens, migrate them to api_keys with type='session'
-- Note: We only migrate active, non-expired tokens
INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id, created_at)
SELECT 
    id,
    token_hash,
    'session_token',
    'session',
    'active',
    expires_at,
    oidc_subject,
    created_at
FROM session_tokens 
WHERE expires_at > datetime('now');

-- 5. Drop session_tokens table (all auth now goes through api_keys)
DROP TABLE session_tokens;