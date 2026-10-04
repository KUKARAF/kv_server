## kv-osmosis (kv.osmosis.page)

A lightweight KV store for non-critical secrets and semi-public data (e.g. deployed app versions). Access control is the core feature.

---

### Stack

- **Rust (axum)** — HTTP service, all business logic, OIDC flow, access control middleware, serves static admin panel files
- **SQLite (sqlx + WAL mode)** — data storage, single file, easy backup
- **HTMX** (via CDN) — admin panel frontend making REST calls to the Rust service
- **Caddy (external, existing)** — TLS termination for `kv.osmosis.page`, proxies to Rust service. See [External Caddy config](#external-caddy-config) below.
- **Docker Compose** — non-secret config (domain `kv.osmosis.page`, daily rate limit, port, OIDC client ID)

Secrets (Authentik client secret, session signing key) live in `.env`, not in Docker Compose.

---

### Data model

**`kv_entries`**
- `key` (text, primary key) — flat keyspace
- `value` (text)
- `ttl_hours` (real, nullable — null = no expiry)
- `ttl_sliding` (bool — true = reset expiry on each read, false = fixed from creation)
- `expires_at` (datetime, nullable — maintained automatically)
- `open_access` (bool — if true, readable without any API key)
- `created_at`

**`api_keys`**
- `id`
- `key_hash` (sha256 — never store plaintext)
- `label`
- `type` — `standard` | `one_time` | `approval_required`
- `status` — `active` | `pending_approval` | `used` | `revoked`
- `expires_at` (nullable)
- `created_at`
- `last_used_at`

**`api_key_scopes`**
- `id`
- `api_key_id` (fk → api_keys)
- `key_pattern` (text — e.g. `payments-*` or exact `app-version`)
- `ops` (text — comma-separated subset of `read,write,delete,list`)

One API key can have multiple scope rules. Access granted if any rule matches key + operation.

**`approval_requests`**
- `id`
- `api_key_id` (fk → api_keys)
- `emoji_sequence` (text — e.g. "🦊🌊🎸", shown to both requester and admin for out-of-band confirmation)
- `status` — `pending` | `approved` | `rejected` | `expired`
- `requested_at`
- `expires_at` (approval window, e.g. 10 min)

**`session_tokens`**
- `id`
- `token_hash`
- `oidc_subject` (from Authentik)
- `email`
- `expires_at` (10h from creation, non-renewable)
- `created_at`

---

### Access control — request lifecycle

Enforced in axum middleware before the handler runs:

1. **Extract** `X-Api-Key` header (or none for open-access entries)
2. **Validate key**: hash lookup, check `status = active`, check `expires_at`
3. **Type checks**:
   - `one_time`: mark `status = used` atomically (SQLite transaction), reject if already used
   - `approval_required`: reject if not yet approved
4. **Scope check**: for the requested key + operation, verify a matching scope rule exists
5. **Handler runs**

Admin endpoints require a valid session token instead of an API key.

### Access modes

1. **Standard** — long-lived key, optional expiry, scope rules
2. **One-time** — valid for a single successful request, then `status = used`
3. **Approval-required** — blocked until admin approves in panel; emoji sequence shown on both sides for out-of-band confirmation (no extra credentials needed)
4. **Open/unauthenticated** — per-entry `open_access` flag; reads allowed without any API key, subject to TTL

---

### TTL / expiry

- Per-entry `ttl_hours` — null means no expiry
- Per-entry `ttl_sliding` — if true, `expires_at` resets on every successful read
- Expired entries filtered in query (`WHERE expires_at IS NULL OR expires_at > now()`)
- Background Tokio task hard-deletes expired entries periodically
- Session tokens: 10h fixed, no renewal

---

### OIDC / session tokens

- Rust service handles the full OIDC flow with Authentik at `auth.osmosis.page`
- On successful login: issue a session token (random, hashed in DB), return plaintext once
- Session token sent as `Authorization: Bearer <token>` on admin API calls
- Not for programmatic/machine use

---

### Admin panel (HTMX)

Served as static files by the Rust service. OIDC-gated. Provides:
- List / create / revoke API keys and their scope rules
- View pending approval requests with emoji sequence — approve / reject
- View KV entries (keys + metadata, values hidden by default)
- View own active session

---

### Device key policies & bans

Device-bound session tokens (minted via session-request approval, `api_keys.device_id` set)
are full admin sessions for their owner. Each registered device can be limited to a subset of
KV entry *names* (migration 0040, `src/device_policy/`):

- `allow_all` (default; no `device_policies` row behaves identically), `allow_list`,
  `deny_list`, `regex` (whole-name match, anchored `^(?:pat)$`, ≤512 chars, size-limited).
  The bare pattern must compile on its own before it is anchored, so unbalanced parentheses
  (`FOO)|(.*`) can't escape the anchors — such patterns are rejected with 400.
- **Device-attributable credential** = any `api_keys` row with `device_id` set: the device's
  own session token AND every credential that device session mints itself (`POST
  /api/admin/keys` of any type, `/session-key`, `/session/cli-token`,
  `/session/device-token`, and session-request approval for its own device). Such credentials
  carry the minting device's id, so its ban and policy follow them on every auth path
  (AdminAuth cookie/Bearer, `/kv` Bearer, `X-Api-Key`). Tokens minted from an OIDC/admin
  (non-device) session are **not** device-attributed.
- **Violation** = a device-attributable request to read, write, delete or import a specific KV
  entry the policy doesn't allow: `GET/PUT/DELETE /kv/{key}` (Bearer or `X-Api-Key`),
  `GET /api/admin/kv/{key}/value`, `PUT /api/admin/kv`, `DELETE /api/admin/kv/{key}`,
  `POST /api/admin/kv/device`, `POST /api/admin/kv/import` (every resulting name, prefix
  included; checked before anything is written, so one bad name imports nothing),
  `GET /api/{admin/,}devices/{id}/kv/{key}`, provisioned-key envelopes linked to KV entries.
  A disallowed name is a violation whether or not the entry exists (no existence oracle).
  The device is banned for `DEVICE_BAN_BASE_SECS` (default 86400, clamped to ≥ 60 with a
  warning) × 2^(n-1), capped at 30 days, a high-priority notification is sent (names only),
  and the response is 403 `{"error":"device banned"}`. Concurrent violations escalate once.
- **Listings never ban**: for a restricted device, names-only listings (`GET /kv`,
  `GET /api/admin/kv`, `GET /api/admin/kv/keys`, the access log, `allowed_keys` in
  `GET /api/admin/keys`) are filtered to the names its policy allows.
- **While banned** every device-attributable request (AdminAuth / Bearer KV / `X-Api-Key`,
  session-request create, poll/claim, approve for that device) gets the same 403. The
  unauthenticated `POST /session-request/challenge` deliberately does **not** check bans (it
  would be a ban-status oracle); possession-proven `create_request` does. Expired bans are
  ignored and cleared by TTL cleanup; `ban_count` is kept so repeat offences escalate.
- Bans/violations are **not auth failures**: no `AuthFailed` marker, neither per-IP counter moves.
- A policy-restricted device (mode ≠ `allow_all`) is refused (plain 403 "not permitted for
  this device", no ban) on identity/credential management: minting credentials, management-key
  envelopes, WebAuthn passkey register begin/finish and credential delete, device register
  begin/finish, device-proposal link, and approving a session request for any device other
  than itself (`ensure_may_manage_credentials`). `allow_all` devices keep full behaviour (the
  Android app approves other devices' session requests). No device can delete itself.
- **Device deletion** (`DELETE /api/admin/devices/:id`) deletes, in one transaction, every
  `api_keys` row attributed to the device (its sessions and the tokens it minted) with their
  dependents (`api_key_allowed_keys`, `approval_requests`, `device_auth_requests`), plus its
  `session_requests`, `session_request_challenges`, linked `device_proposals`, policy and ban
  rows. Attributed keys are never detached (`device_id = NULL` would make a live device token
  an unrestricted non-device credential).
- `GET /api/{admin/,}devices/{id}/kv/{key}` called by a **non-device** caller (or another
  device) still applies the *path* device's ban and policy, as a plain 403 with no ban
  recorded. This is intentional: kv_cli on the device host may fetch with an approval token,
  and a path parameter must never be able to get a device banned.
- Management API `/api/admin/device-policies` (`GET /`, `PUT /:device_id`,
  `DELETE /:device_id/ban`, `GET /bans`) is closed to device-attributable credentials (403) so
  a device can't relax its own policy or unban itself — including via tokens it minted.
- **Residual risks**: (1) tokens minted from a non-device (OIDC/admin) session and stored on a
  device host — e.g. a kv_cli approval token — are not device-attributed and bypass the
  device's policy, ban and the policy-admin lockout. (2) Devices enrolled by an `allow_all`
  device before it was restricted are separate devices with their own (default `allow_all`)
  policies; restricting the enroller does not restrict them. (3) `ban_count` never decays.

---

### Rate limiting

Daily request limit configured via Docker Compose env var, enforced in axum middleware (tower-governor or similar). Resets at midnight UTC.

---

### External Caddy config

Add to the existing `osmosis.page` Caddy instance:

```caddyfile
kv.osmosis.page {
  reverse_proxy <host>:<port>
}
```

Caddy handles TLS automatically. The Rust service listens on plain HTTP internally.

---

### Deferred (v2)

- Value encryption at rest
