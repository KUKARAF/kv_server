-- Device-bound session tokens. Instead of storing the approved session token in
-- plaintext (plaintext_token) and handing it to whoever polls, approval now delivers
-- the token ECDH-wrapped to a registered device's public key. Only that device's
-- private key can decrypt it, so a spoofed/coerced/DB-leaked approval yields ciphertext
-- that is useless to anyone but the real client.
--
-- device_id: which registered device the token is wrapped to (chosen at create time).
-- wrap_*: the device-KV envelope (same shape as device_kv_bodies + device_kv_recipients),
--         all base64. Populated at approval, cleared on delivery.
-- plaintext_token is intentionally left in place for back-compat but is no longer written.
ALTER TABLE session_requests ADD COLUMN device_id TEXT REFERENCES devices(id);
ALTER TABLE session_requests ADD COLUMN wrap_key_type      TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_nonce         TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_ciphertext    TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_aad           TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_ephemeral_pub TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_dek_nonce     TEXT;
ALTER TABLE session_requests ADD COLUMN wrap_encrypted_dek TEXT;
