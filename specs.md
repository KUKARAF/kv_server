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
