# Auth Counter Expected Behaviour

Two independent per-IP counters (IPv6 bucketed to /64):

- **Rate counter** — in-memory `DashMap<IpAddr, u32>` in `src/middleware/rate_limit.rs`,
  resets daily at midnight. Increments only when a response carries the `AuthFailed`
  marker. There are **no credential-shape exemptions**: Bearer, session cookie, and
  `X-Api-Key` are all counted the same way — success is free, failure counts.
- **Block counter** — `blocked_ips.failed_count` in SQLite via `record_auth_failure()`
  in `src/middleware/ip_block.rs`. At `AUTH_FAILURE_THRESHOLD` the IP is blocked for
  `AUTH_BLOCK_BASE_SECS`, doubling per repeat offense (capped 30d), then auto-expiring.

Expired sessions return `AppError::SessionExpired` — the same 401 body as `Unauthorized`
but **without** the `AuthFailed` marker — so a legit client re-authing never accrues on
either counter.

## Expected behaviour per scenario

| #  | Scenario                                   | Rate counter | Block counter |
|----|--------------------------------------------|--------------|---------------|
| 1  | No credentials, protected endpoint         | ++           | ++            |
| 2  | Unknown Bearer token (not a session key)   | ++           | —             |
| 3  | Valid, active Bearer session token         | —            | — (resets)    |
| 4  | Expired Bearer session token               | —            | —             |
| 5  | Revoked/used Bearer session token          | ++           | ++            |
| 6  | `X-Api-Key` not found in DB                 | ++           | ++            |
| 7  | `X-Api-Key` valid, active                   | —            | — (resets)    |
| 8  | `X-Api-Key` expired                         | ++           | ++            |
| 9  | `X-Api-Key` revoked/used                    | ++           | ++            |
| 10 | `X-Api-Key` valid, wrong scope              | —            | —             |
| 11 | No credentials, open-access GET             | —            | —             |

Notes:

- **Unknown Bearer (2)** is rate-counted but not block-counted: purged session rows make
  a stale-but-formerly-valid cookie indistinguishable from a random token, so it must not
  contribute to a permanent-ish block — the self-healing daily rate counter is enough.
- **Expired Bearer (4)** is fully benign (`SessionExpired`): neither counter moves, so a
  polling dashboard with a lapsed cookie can't self-ban.
- **Wrong scope (10)** is `Forbidden` (403), not an auth failure — neither counter moves.
