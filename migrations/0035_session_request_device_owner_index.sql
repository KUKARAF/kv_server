-- list_pending/get_request/approve/reject now join devices to display the device's real,
-- immutable, owner-scoped name and to check the approving/rejecting admin owns that device
-- (see session_request/handlers.rs). Index the join column.
--
-- approval_token_hash / approval_envelope (0034) and confirm_code_hash (0032) are no longer
-- written or read as of this migration's accompanying code change; left in place (nullable,
-- unused) rather than dropped, matching this repo's established pattern for deprecated
-- columns (see 0033's plaintext_token comment).
CREATE INDEX IF NOT EXISTS idx_session_requests_device_id ON session_requests(device_id);
