# Device Rework — Future Work

Prerequisites (migration, Rust module, registration page) must be done first.

## Todo

- [ ] Link session key `owner_id` / `label` to the `devices` table entry that owns the session
- [ ] Sign a server-issued challenge with the device private key to prove device identity (server verifies with stored public key)
- [ ] Device management UI — list registered devices, revoke a device
