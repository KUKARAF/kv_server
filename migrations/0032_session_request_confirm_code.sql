-- A human-verifiable, bcrypt-hashed confirmation code the requester must relay to the
-- approving admin out-of-band. Without this, `approve` had no proof that the party
-- being approved is the one the admin actually intends to grant a session to — an
-- attacker could POST their own unauthenticated create_request with a spoofed label
-- and get it approved instead of (or alongside) the real request.
ALTER TABLE session_requests ADD COLUMN confirm_code_hash TEXT;
