-- Device-encrypted one-time approval token, replacing the emoji confirm_code.
--
-- At create time the server mints a one-time token, ECDH-wraps the plaintext token to
-- the request's device public key (same envelope shape as the session token / device-KV),
-- and stores:
--   approval_envelope   TEXT — the wrapped token as JSON (device-KV envelope), served
--                              idempotently while pending so the device can display it.
--   approval_token_hash TEXT — sha256 of the plaintext token; the admin must submit the
--                              token (relayed out-of-band from the device) to approve.
-- The plaintext token is never stored. The old confirm_code_hash column (0032) is left in
-- place for back-compat but is no longer populated.
ALTER TABLE session_requests ADD COLUMN approval_token_hash TEXT;
ALTER TABLE session_requests ADD COLUMN approval_envelope   TEXT;
