# KV Manager - Codebase Analysis

## Overview
A lightweight KV store with advanced access control, one-time API keys, and approval-based authentication. Built with Rust (axum) and SQLite.

---

## 1. ONE-TIME API KEY LIFECYCLE

### Creation Flow
**Endpoint:** `POST /api/admin/keys`
**Handler:** `src/admin/handlers.rs::create_key()` (lines 50-123)

```
Admin creates one-time key
  ↓
POST request with:
  {
    "label": "share-api-key-with-john",
    "key_type": "one_time",
    "entry_scope": "api_keys/staging",
    "scopes": []
  }
  ↓
For one-time with entry_scope, auto-generate scope:
  - scope = "api_keys/staging"
  - ops = "read" (hardcoded)
  ↓
Database INSERT:
  api_keys table:
    - id: UUID
    - key_hash: SHA256(plaintext)
    - label: "share-api-key-with-john"
    - type: "one_time"
    - status: "active"
    - owner_id: authenticated admin's OIDC subject
  
  api_key_scopes table:
    - scope: "api_keys/staging"
    - ops: "read"
  ↓
Response: plaintext key (shown once)
  { "id": "...", "key": "kv_..." }
```

### Consumption Flow
**Middleware:** `src/middleware/api_key.rs::FromRequestParts::from_request_parts()` (lines 233-247)

```
Client request with X-Api-Key header
  ↓
1. Hash key with SHA256
2. Query database:
     SELECT id, type, status, expires_at, owner_id FROM api_keys WHERE key_hash = ?
  ↓
3. Validate key:
     - Check status = 'active'
     - Check not expired
  ↓
4. Type-specific checks:
     For "one_time":
       - Allowed only if status = 'active'
  ↓
5. Scope check:
     - Fetch entry's scope from kv_entries
     - Query allowed scopes for this key from api_key_scopes
     - Call check_scope() function
     - If ANY scope rule allows the operation → proceed
     - If NO scope rule allows → return 403 Forbidden: "insufficient scope"
  ↓
6. CONSUME KEY (CRITICAL):
     UPDATE api_keys
     SET status = 'used', last_used_at = datetime('now')
     WHERE id = ? AND status = 'active' AND type = 'one_time'
  ↓
     If rows_affected() == 0:
       - Key already consumed
       - Return 403: "one-time key already used"
  ↓
7. Handler runs (GET, PUT, DELETE on KV entry)
```

**KEY INSIGHT:** One-time consumption happens AFTER scope validation passes. This prevents:
- Consuming key on failed scope checks
- Consuming key on malformed requests
- The key being marked as "used" when it shouldn't have been

---

## 2. KV ENTRY MANAGEMENT

### Data Model
**Table: kv_entries** (from migrations/0004_ownership.sql)

```sql
CREATE TABLE kv_entries (
    key         TEXT    NOT NULL,
    owner_id    TEXT    NOT NULL,  -- OIDC subject (admin ownership)
    value       TEXT    NOT NULL,
    scope       TEXT,               -- hierarchical scope for access control
    ttl_hours   REAL,               -- null = no expiry
    ttl_sliding INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT,               -- computed from ttl_hours
    open_access INTEGER NOT NULL DEFAULT 0,
    zt_ciphertext, zt_wrapped_dek, zt_nonce, zt_aad, zt_prf_salt, zt_credential_id,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (key, owner_id)
);
```

### "Tick One Time" Scenario
**Mentioned in specs.md:73:** "one_time: mark `status = used` atomically"

This refers to creating a temporary, one-use KV entry tied to a one-time key:

```
Admin workflow:
1. Create one-time key with entry_scope = "api_keys/staging"
   - Key gets automatic "read" scope for this entry scope
   - Key status = "active"

2. Share key URL with external user (e.g., share.html page)
   
3. User loads URL in first tab/browser:
   - Sends request with X-Api-Key header
   - Middleware validates scope against entry
   - Scope check passes ✓
   - Entry can be a KV lookup (GET /kv/api_keys/staging/foo)
   - Key status changes: active → used ✓
   
4. User opens same URL in NEW TAB/DIFFERENT BROWSER:
   - Sends same X-Api-Key header
   - Middleware finds key again
   - Status = "used" (from step 3)
   - Authentication FAILS with 403: "one-time key already used" ✓
```

---

## 3. "INSUFFICIENT SCOPE" ERROR IN NEW TAB

### Root Cause Analysis
**Error occurs:** When a one-time key URL is accessed in a new tab after first use
**Error message:** 403 Forbidden: "insufficient scope"
**Actual problem:** Not a scope issue, but a one-time key consumption issue

### The Bug Scenario

```
Scenario: One-time key with entry_scope = "osmosis/media"
Entry exists: key = "version", scope = "osmosis/media"

Tab 1: User accesses key for FIRST TIME
  ↓
  Request: GET /kv/version with X-Api-Key=<one_time_key>
  ↓
  Middleware flow:
    1. Look up key → found, status = "active"
    2. Fetch entry scope: "osmosis/media"
    3. Fetch allowed scopes for this key:
       - scope = "osmosis/media", ops = "read"
    4. Call check_scope(&scopes, Some("osmosis/media"), "read")
       → scope_covers("osmosis/media", "osmosis/media") → True
       → ops has "read" → True
       → PASSES scope check ✓
    5. Consume key:
       UPDATE api_keys SET status = 'used'
       WHERE id = ? AND status = 'active' AND type = 'one_time'
       → rows_affected = 1 ✓
    6. Handler executes → 200 OK
    7. Key is now status = "used"

Tab 2: User opens SAME URL (or new tab)
  ↓
  Request: GET /kv/version with X-Api-Key=<one_time_key>
  ↓
  Middleware flow:
    1. Look up key → found, status = "used" ← CHANGED
    2. Check status in type-specific section:
       For "one_time", allowed status = "active" only
       Current status = "used"
       → Does NOT immediately reject in type-specific section
    3. Fetch entry scope: "osmosis/media"
    4. Fetch allowed scopes for this key:
       - scope = "osmosis/media", ops = "read"
    5. Call check_scope(&scopes, Some("osmosis/media"), "read")
       → PASSES (same as before)
    6. Try to consume key:
       UPDATE api_keys SET status = 'used'
       WHERE id = ? AND status = 'active' AND type = 'one_time'
       → rows_affected = 0 ← No rows matched (status != 'active')
    7. Return 403: "one-time key already used" ✓

BUT WAIT - OBSERVED BEHAVIOR: User sees "insufficient scope", not "already used"
```

### Why "Insufficient Scope" Error?

Looking at `src/middleware/api_key.rs` lines 152-196:

```rust
match api_key.key_type.as_str() {
    "zero_trust" => { /* check */ }
    "approval_required" => { /* check */ }
    _ => {  // ← "one_time" falls here
        if api_key.status != "active" {
            return Err(AppError::Unauthorized);  // NOT returned for one_time!
        }
    }
}
```

**BUG:** For "one_time" keys, when status != "active", the code falls through to the generic branch:
- Checks `if api_key.status != "active"` → TRUE
- Returns `AppError::Unauthorized` (401)

But the scope check happens BEFORE this! Let me re-read the code...

Actually, looking at lines 198-231, the scope check happens AFTER type checks. But for one_time:

```rust
// Type-specific checks (line 152)
match api_key.key_type.as_str() {
    // ...
    _ => {
        if api_key.status != "active" {
            return Err(AppError::Unauthorized);  // line 193
        }
    }
}

// Then scope check (lines 199-231)
let scopes = sqlx::query_as!(ScopeRule, "SELECT ...");
// ... fetch entry_scope ...
if !check_scope(&scopes, check_scope_val, op.as_str()) {
    return Err(AppError::Forbidden("insufficient scope".to_string()));  // line 230
}

// Then consume one-time key (lines 234-247)
if api_key.key_type == "one_time" { ... }
```

**ACTUAL FLOW FOR USED ONE-TIME KEY:**

```
Tab 2 (after key used):
  1. Type check: status = "used" (not "active")
     → Return 401 Unauthorized (caught before scope check)

But scope check is AFTER type check:
  2. If type check passed, proceed to scope check
```

Wait, I'm reading this wrong. Let me trace again more carefully...

Looking at line 153-196 (type-specific checks):
- "one_time" keys don't have special handling!
- They fall through to the generic `_` case
- Generic case: `if api_key.status != "active" { return Err(AppError::Unauthorized); }`

So a "used" one-time key (status = "used") would be rejected at line 193 with 401 Unauthorized.

But the problem states "insufficient scope" is returned. This suggests:
1. The scope check is somehow happening before the status check
2. OR there's a logic error in scope validation

Let me check if there's conditional logic for one_time in scope handling...

Actually, looking more carefully at lines 207-221:

```rust
// For reads/writes/deletes on a specific key, fetch the entry's scope
let entry_scope: Option<String> = if op != Op::List && !kv_key.is_empty() {
    sqlx::query_scalar!(
        "SELECT scope FROM kv_entries WHERE key = ? AND owner_id = ?
         AND (expires_at IS NULL OR expires_at > datetime('now'))
         LIMIT 1",
        kv_key, api_key.owner_id
    )
    .fetch_optional(&state.pool)
    .await?
    .flatten()
} else {
    None
};
```

**KEY ISSUE:** The entry_scope is fetched from `kv_entries` using `api_key.owner_id`.

But one-time keys with entry_scope create an AUTOMATIC scope for access control, not necessarily tied to a specific KV entry!

If there's NO actual KV entry with that scope yet, or if it was deleted, then:
- entry_scope = None
- check_scope(&scopes, None, "read") is called
- The scope rule is scope = "osmosis/media", ops = "read"
- But None entry_scope requires scope = "*" for unscoped entries (see scope.rs:26-29)
- scope_covers("osmosis/media", null_scope) → False
- Returns 403: "insufficient scope" ✓

**THIS IS THE BUG!**

One-time keys with entry_scope are created with an automatic scope rule EVEN IF NO ENTRY EXISTS.
When the entry doesn't exist (or is deleted, or expired), the scope check fails before the one-time consumption happens.
```

### The Real Issue

The "insufficient scope" error occurs in a new tab when:

1. **One-time key created with entry_scope** (e.g., "api_keys/staging")
   - Automatic scope rule added: scope = "api_keys/staging", ops = "read"
   - No actual KV entry needs to exist

2. **First access attempt** (Tab 1)
   - Entry exists with scope = "api_keys/staging"
   - Scope check passes
   - Key consumed → status = "used"
   - 200 OK

3. **Second access attempt** (Tab 2, new session)
   - Key lookup: status = "used"
   - Type check for one_time: expects "active", got "used"
     - Should return 401 Unauthorized
   - But if somehow scope check runs first:
     - Entry doesn't exist (deleted/expired)
     - entry_scope = None
     - check_scope(&scopes, None, "read") → False
     - Returns 403: "insufficient scope"

---

## 4. SCOPE VALIDATION LOGIC

### Scope Rules System
**File:** `src/keys/scope.rs` (lines 1-94)

```rust
pub struct ScopeRule {
    pub scope: String,  // "osmosis", "*", or any scope prefix
    pub ops: String,    // "read,write,delete,list"
}

/// Hierarchical scope matching:
/// - "*" matches everything
/// - "osmosis" matches "osmosis" AND "osmosis/media", "osmosis/ai", etc.
/// - "osmosis" does NOT match "osmosisX" or "osmosis2" (requires "/" or exact match)
pub fn scope_covers(allowed: &str, entry_scope: &str) -> bool {
    allowed == "*"
        || allowed == entry_scope
        || entry_scope.starts_with(&format!("{allowed}/"))
}

/// Checks if a scope rule permits operation on an entry with given scope
/// Unscoped entries (scope=None) only allowed if rule.scope == "*"
pub fn check_scope(scopes: &[ScopeRule], entry_scope: Option<&str>, op: &str) -> bool {
    scopes.iter().any(|rule| {
        let scope_ok = match entry_scope {
            None => rule.scope == "*",      // Unscoped requires wildcard
            Some(s) => scope_covers(&rule.scope, s),
        };
        scope_ok && rule.ops.split(',').any(|o| o.trim() == op)
    })
}
```

### Call Sites

**In `src/kv/handlers.rs:292` (list_entries)**
```rust
if auth.api_key_id.is_some() && !auth.allowed_scopes.is_empty() {
    rows.into_iter()
        .filter(|e| check_scope(&auth.allowed_scopes, e.scope.as_deref(), "list"))
        .collect()
}
```

**In `src/middleware/api_key.rs:224` (main validation)**
```rust
let check_scope_val = if op == Op::List { None } else { entry_scope.as_deref() };
if !check_scope(&scopes, check_scope_val, op.as_str()) {
    notify::send(..., "Auth failure: scope denied for key...");
    return Err(AppError::Forbidden("insufficient scope".to_string()));
}
```

### Test Cases
From `src/keys/scope.rs:34-94`:

```rust
#[test]
fn scope_covers("osmosis", "osmosis");                    // ✓ exact
#[test]
fn sub_scope("osmosis", "osmosis/media");                 // ✓ child
#[test]
fn no_partial_prefix("osmosis", "osmosisX");              // ✗ no slash
#[test]
fn unscoped_requires_wildcard(None, "*");                 // ✓ wildcard only
#[test]
fn check_scope_any_rule([osmosis/read, other/read], ...);// ✓ multiple rules
```

---

## 5. API ENDPOINTS

### Key Management Endpoints

| Method | Endpoint | Handler | Auth | Purpose |
|--------|----------|---------|------|---------|
| POST | `/api/admin/keys` | `create_key()` | Admin Session | Create standard/one_time/approval_required/zero_trust key |
| GET | `/api/admin/keys` | `list_keys()` | Admin Session | List all keys with scopes |
| POST | `/api/admin/keys/{id}/revoke` | `revoke_key()` | Admin Session | Revoke active key |
| DELETE | `/api/admin/keys/{id}` | `delete_key()` | Admin Session | Delete revoked/used key |
| POST | `/api/admin/keys/{id}/request-approval` | `request_approval()` | Public | Trigger approval_required flow |

### KV Entry Endpoints

| Method | Endpoint | Handler | Auth | Purpose |
|--------|----------|---------|------|---------|
| GET | `/kv/{key}` | `get_entry()` | API Key OR open_access | Read entry |
| PUT | `/kv/{key}` | `upsert_entry()` | API Key + owner | Create/update entry |
| DELETE | `/kv/{key}` | `delete_entry()` | API Key + owner | Delete entry |
| GET | `/kv` | `list_entries()` | API Key + owner | List all entries (filtered by scope) |
| POST | `/kv/request-access` | `request_access()` | API Key + approval_required | Trigger approval emoji |

### Approval Endpoints

| Method | Endpoint | Handler | Auth | Purpose |
|--------|----------|---------|------|---------|
| GET | `/api/admin/approvals` | `list_approvals()` | Admin Session | List pending approvals |
| POST | `/api/admin/approvals/{id}/approve` | `approve_request()` | Admin Session | Approve with emoji |
| POST | `/api/admin/approvals/{id}/reject` | `reject_request()` | Admin Session | Reject approval |

---

## 6. AUTHENTICATION FLOW

### Middleware Extraction
**File:** `src/middleware/api_key.rs:FromRequestParts::from_request_parts()`

```
Request arrives
  ↓
1. Check Authorization: Bearer token (session token)
   - If valid → full access as admin owner
   - If invalid → continue to API key check
  ↓
2. Check X-Api-Key header
   - Extract and hash with SHA256
   - Query api_keys WHERE key_hash = ?
   - If not found → 401 Unauthorized
   ↓
3. Validate key status and expiry
   - status = 'revoked' or 'used' → 401 Unauthorized
   - expires_at in past → 401 Unauthorized
   ↓
4. Type-specific validation
   - approval_required: if not active, check for pending requests
   - zero_trust: must be active
   - standard/one_time: must be active
   ↓
5. Fetch entry's scope from kv_entries
   ↓
6. Scope check against api_key_scopes
   - If denied → 403 Forbidden: "insufficient scope"
   ↓
7. For one_time keys: UPDATE status = 'used'
   - If rows_affected = 0 → already used, 403
   ↓
8. Return ApiKeyAuth with:
   - owner_id: api_key.owner_id
   - api_key_id: api_key.id
   - op: derived from HTTP method
   - allowed_scopes: ScopeRule[]
```

---

## 7. KEY FINDINGS & ISSUES

### Finding 1: One-Time Key Consumption Order
✓ **CORRECT IMPLEMENTATION**

One-time keys are marked as "used" AFTER scope validation passes (line 234).
- Prevents wasting the key on invalid requests
- Atomic update with `AND status = 'active'` guard clause

### Finding 2: Insufficient Scope Error Root Cause
⚠️ **POTENTIAL BUG - Entry Scope Mismatch**

When a one-time key with `entry_scope = "api_keys/staging"` is created:
- Automatic scope rule created: scope="api_keys/staging", ops="read"
- NO actual KV entry is required to exist at creation time

When accessed:
- If entry doesn't exist: entry_scope = None
- check_scope(&scopes, None, "read") with scope="api_keys/staging"
- scope_covers("api_keys/staging", null) → False (None only matches "*")
- Returns 403: "insufficient scope"

**The error is technically correct, but semantically confusing:**
- Error suggests scope is insufficient
- Real cause: entry doesn't exist or scope mismatch

**Solution:** 
1. Entry must exist with matching scope
2. OR auto-create entry when one-time key with entry_scope is created
3. OR document that entry_scope requires the entry to pre-exist

### Finding 3: Scope Covers Logic
✓ **WELL DESIGNED**

Hierarchical scoping with proper tests:
- `scope_covers("osmosis", "osmosis/media")` → True
- `scope_covers("osmosis", "osmosisX")` → False (no slash)
- Unscoped entries only accessible with "*" scope

### Finding 4: One-Time Key Type Check
⚠️ **INCONSISTENT STATE HANDLING**

Line 234: `if api_key.key_type == "one_time"`

One-time keys with status="used":
- Type check at line 153-196 uses generic case: checks `if status != "active"`
- Should return 401 Unauthorized for used keys
- But scope check happens BEFORE consumption attempt
- If scope check fails first, returns 403 "insufficient scope"

### Finding 5: Owner ID Requirement
✓ **SECURITY FEATURE**

Every KV entry and API key is tied to owner_id (OIDC subject).
- Prevents cross-owner access
- One admin's one-time key cannot access another admin's entries
- Primary key: (key, owner_id) for kv_entries

---

## 8. SUMMARY TABLE: ONE-TIME KEY SCENARIOS

| Scenario | Entry Exists | Entry Scope | Key Scope | First Use | Second Use |
|----------|--------------|-------------|-----------|-----------|------------|
| Proper flow | Yes | "api/v1" | "api/v1" | ✓ 200 | ✗ 403 "already used" |
| Scope mismatch | Yes | "api/v2" | "api/v1" | ✗ 403 "insufficient scope" | ✗ 403 |
| Entry missing | No | N/A | "api/v1" | ✗ 403 "insufficient scope" | ✗ 403 |
| Wildcard access | Yes | "anything" | "*" | ✓ 200 | ✗ 403 "already used" |

---

## 9. DATABASE SCHEMA KEY TABLES

### api_keys
```sql
id TEXT PRIMARY KEY
key_hash TEXT UNIQUE -- SHA256 of plaintext key
label TEXT
type TEXT CHECK (type IN ('standard','one_time','approval_required','zero_trust'))
status TEXT CHECK (status IN ('active','pending_approval','used','revoked'))
expires_at TEXT -- nullable
owner_id TEXT -- OIDC subject
created_at TEXT DEFAULT (datetime('now'))
last_used_at TEXT -- nullable
```

### api_key_scopes
```sql
id TEXT PRIMARY KEY
api_key_id TEXT REFERENCES api_keys(id) ON DELETE CASCADE
scope TEXT -- hierarchical scope like "osmosis/media"
ops TEXT -- "read,write,delete,list"
```

### kv_entries
```sql
key TEXT NOT NULL
owner_id TEXT NOT NULL
value TEXT
scope TEXT -- nullable, for access control hierarchies
ttl_hours REAL -- nullable
ttl_sliding INTEGER DEFAULT 0
expires_at TEXT -- nullable
open_access INTEGER DEFAULT 0 -- bypass auth if 1
created_at TEXT DEFAULT (datetime('now'))
PRIMARY KEY (key, owner_id)
```

---

## 10. CODE LOCATIONS REFERENCE

| Component | File | Lines |
|-----------|------|-------|
| Key generation | `src/keys/generate.rs` | 1-35 |
| Scope validation | `src/keys/scope.rs` | 1-94 |
| Middleware auth | `src/middleware/api_key.rs` | 52-270 |
| KV handlers | `src/kv/handlers.rs` | 99-299 |
| Admin handlers | `src/admin/handlers.rs` | 50-123, 233-247 |
| Models | `src/admin/model.rs`, `src/kv/model.rs` | - |
| Error types | `src/error.rs` | 1-93 |

