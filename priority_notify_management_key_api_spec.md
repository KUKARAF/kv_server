## priority-notify management key — integration spec

How the kv server provisions, rotates, and revokes its own **priority-notify API tokens**
programmatically, using a priority-notify **management key** (an OpenRouter-style provisioning
credential).

This is about priority-notify's management key — the credential that manages priority-notify
tokens. It is unrelated to kv-manager's own `management_keys` module (`src/management_keys/`),
which provisions kv keys for devices. Different systems, same word.

> **Depends on**: the management-key feature being deployed to `notifications.osmosis.page`
> (priority-notify `POST/GET/DELETE /api/tokens/management-key` + `scope` on tokens). Until then,
> keep pasting a `NOTIFY_API_KEY` by hand as today.

---

### Why

Today the kv server sends notifications by reading a single plaintext client token from the
reserved `NOTIFY_API_KEY` KV entry and POSTing to priority-notify (`src/notify.rs::send`). That
token is minted by hand in the priority-notify UI and pasted in — it can't be rotated without a
human, and if it leaks there's no self-service way to cut it.

priority-notify now supports a **management key**: one per user, generated once, that can
**create / list / revoke** that user's API tokens over HTTP. Giving the kv server the management
key lets it own the full lifecycle of its send-token — bootstrap it, rotate it on a schedule,
and revoke a leaked one — without a human touching the priority-notify UI again.

---

### Two credentials — the mental model

The kv server holds **two distinct priority-notify credentials**. Keep them separate:

| Credential | Reserved KV entry | Scope / power | Used for |
|---|---|---|---|
| **Management key** | `NOTIFY_MANAGEMENT_KEY` | Manage tokens (create/list/revoke). **Cannot send notifications.** | Provisioning the send-token |
| **Send token** | `NOTIFY_API_KEY` (existing) | `write` (send only, not delete/read) | `notify.rs::send` |

Consequences to bake in:

- The management key is **not** a notification credential. `POST /api/notifications/` with it
  returns **401**. Never try to send with it.
- The send token is `write`-only, so it can **only** create notifications — it cannot list, mark
  read, delete, or manage other tokens. That's the least privilege the kv server needs.
- The kv server **cannot mint its own management key** — `POST /api/tokens/management-key` requires
  a logged-in browser session. A human generates it once in the priority-notify UI and stores it in
  `NOTIFY_MANAGEMENT_KEY`. From then on everything else is automatable.

Both entries **must** be owner-scoped to the admin exactly like `NOTIFY_API_KEY` is today (see
`notify.rs::fetch_key` → `admin_owner_id`, `config::ADMIN_EMAIL`), so a non-admin's entry can never
be used.

---

### priority-notify API reference

- **Base URL**: `https://notifications.osmosis.page` (same host `notify.rs` already posts to).
- **Auth**: `Authorization: Bearer <token>`. Token-manageable endpoints accept the management key.
- **Content type**: `application/json`.

#### Token management (management key OR browser session)

**Create a token** — `POST /api/tokens/`

```json
{ "name": "kv-manager", "device_type": "other", "scope": "write" }
```

- `scope` ∈ `write` (create only) · `read` (read + mark-read) · `delete` (delete only) ·
  `full` (everything — do **not** use here). Omitted → defaults to `write`.
- `device_type` ∈ `android` · `gnome` · `other`. The kv server is a service → `other`.
- **201** returns the plaintext token **once** — capture it now, it is never shown again:

```json
{ "id": "…uuid…", "name": "kv-manager", "device_type": "other",
  "scope": "write", "created_at": "…", "last_used_at": null,
  "expires_at": null, "token": "PLAINTEXT-SHOWN-ONCE" }
```

**List tokens** — `GET /api/tokens/` → **200**, array of the above **without** `token`. Use this to
find the `id` of an old token to revoke during rotation.

**Revoke a token** — `DELETE /api/tokens/{id}` → **204**, or **404** if it isn't yours / doesn't
exist.

#### Management-key lifecycle (browser session only — human-operated)

Listed for completeness; the kv server does not call these.

- `POST /api/tokens/management-key` → **201** `{ created_at, key }` (plaintext once);
  **409** if one already exists (only one per user — revoke before regenerating).
- `GET /api/tokens/management-key` → **200** `{ exists, created_at, last_used_at }`.
- `DELETE /api/tokens/management-key` → **204**, or **404** if none.

#### Errors the kv server must handle

| Status | Meaning | Action |
|---|---|---|
| **401** | Missing/invalid credential (e.g. tried to send with the management key, or key was revoked) | Log; do not retry blindly. If persistent, the management key is gone → alert admin to re-provision. |
| **403** | Token scope insufficient for the operation | Programming error — you used a token whose scope doesn't cover the call. |
| **404** | Token id not found on revoke | Treat as already-gone; safe to ignore during rotation. |
| **409** | Management key already exists | Only relevant to the human bootstrap step. |

---

### Storage & scoping in kv

Add one reserved entry, mirroring `NOTIFY_API_KEY` exactly:

- **`NOTIFY_MANAGEMENT_KEY`** — the priority-notify management key (plaintext bearer).
  - Owner-scoped to `admin_owner_id` (as `NOTIFY_API_KEY` is).
  - Treat as reserved: reject writes from anyone but the admin owner, same guard as the send key.
  - Never expose in list/read responses to non-admin callers.

`NOTIFY_API_KEY` stays exactly as-is — but it becomes a value the kv server **writes itself**
(the plaintext from a `POST /api/tokens/` response) rather than a hand-pasted value.

---

### Workflows

Fetch the management key the same way `fetch_key` fetches `NOTIFY_API_KEY` (owner-scoped
`SELECT value FROM kv_entries WHERE key = 'NOTIFY_MANAGEMENT_KEY' AND owner_id = ?`). If it's
absent, skip silently (fire-and-forget, like `notify.rs::send`) and leave a warning.

**1. Bootstrap (one-time, human + automatable tail)**
1. Human logs into priority-notify, generates a management key, stores it in `NOTIFY_MANAGEMENT_KEY`.
2. kv server (or human) provisions the send token:

```bash
MGMT=$(kv get NOTIFY_MANAGEMENT_KEY)
curl -sS -X POST https://notifications.osmosis.page/api/tokens/ \
  -H "Authorization: Bearer $MGMT" -H "Content-Type: application/json" \
  -d '{"name":"kv-manager","device_type":"other","scope":"write"}'
# → capture .token, store as NOTIFY_API_KEY; keep .id for later revocation
```

**2. Rotate `NOTIFY_API_KEY` (safe, zero-downtime order)**
1. `POST /api/tokens/` (write-only) → get the **new** plaintext + id.
2. Overwrite `NOTIFY_API_KEY` with the new plaintext **first**.
3. Only then `DELETE /api/tokens/{old_id}`. Create-before-revoke means no window where the kv
   server has no working send-token. A **404** on the delete is fine (already gone).

**3. Revoke a leaked send-token immediately**
- `DELETE /api/tokens/{id}` with the management key. Then run rotation to restore sending.

**4. Reconcile / inventory**
- `GET /api/tokens/` to list what the kv server has provisioned (e.g. clean up orphaned tokens
  from failed rotations by matching `name == "kv-manager"`).

Reference (Rust, matching `notify.rs`'s `reqwest` + `tokio::spawn` style):

```rust
let client = reqwest::Client::new();
let resp = client
    .post("https://notifications.osmosis.page/api/tokens/")
    .header("Authorization", format!("Bearer {mgmt_key}"))
    .json(&serde_json::json!({
        "name": "kv-manager", "device_type": "other", "scope": "write",
    }))
    .send().await?;
let created: serde_json::Value = resp.error_for_status()?.json().await?;
let new_send_token = created["token"].as_str().unwrap().to_string();
let new_id = created["id"].as_str().unwrap().to_string();
// write new_send_token → NOTIFY_API_KEY, then DELETE old id
```

---

### Security notes

- **Least privilege**: always provision the send-token as `scope: "write"`. Never `full`.
- **Blast radius**: the management key can revoke and mint tokens but cannot read or send
  notifications — a leak lets an attacker disrupt/rotate tokens, not read notification content.
  Still, treat it as a high-value secret: admin-owner-scoped, never logged, never returned to
  non-admin callers.
- **One key**: priority-notify allows exactly one management key per user. If it's compromised, the
  human revokes it in the UI (`DELETE /api/tokens/management-key`), generates a fresh one, and
  updates `NOTIFY_MANAGEMENT_KEY`. Existing send-tokens keep working across that swap.
- **Fire-and-forget**: provisioning failures must not break kv request handling — mirror
  `notify.rs`'s non-blocking `tokio::spawn` + `tracing::warn!` on error.

---

### Implementation pointers (kv-manager)

- `src/notify.rs` — `fetch_key` / `admin_owner_id` show the owner-scoped reserved-entry pattern to
  copy for `NOTIFY_MANAGEMENT_KEY`; `send` shows the `reqwest` + `tokio::spawn` shape.
- `src/config.rs` — `ADMIN_EMAIL` anchors the owner scoping.
- Reserved-entry write guard — reuse whatever already protects `NOTIFY_API_KEY` from non-admin
  writes; extend it to `NOTIFY_MANAGEMENT_KEY`.
