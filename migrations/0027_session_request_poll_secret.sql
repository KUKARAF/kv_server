-- Decouple the poll secret from the request id. The requester receives a separate
-- high-entropy secret (stored here as a SHA-256 hash) required to claim the session token.
ALTER TABLE session_requests ADD COLUMN poll_secret TEXT;
