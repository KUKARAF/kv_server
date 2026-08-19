-- A per-artifact random token, held only by the requesting/proposing device, required to
-- complete the sensitive admin action (session approve; device-proposal load+link). Unlike
-- the deprecated 0034 approval_envelope/approval_token_hash (an ECDH-wrapped token shown to
-- the device, abandoned in favor of device-identity display), this is a plain token embedded
-- in the URL/QR the device shows the admin — closing the gap where an admin dashboard
-- notification alone (no device-sourced link) was sufficient to approve/confirm.
ALTER TABLE session_requests ADD COLUMN approve_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE device_proposals ADD COLUMN confirm_token_hash TEXT NOT NULL DEFAULT '';
