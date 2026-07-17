# Auth Counter Expected Behaviour

Two independent counters:

- **Rate counter** — in-memory `DashMap<IpAddr, u32>` in `src/middleware/rate_limit.rs`, resets daily at midnight
- **Block counter** — `blocked_ips.failed_count` in SQLite via `record_auth_failure()` in `src/middleware/ip_block.rs`, permanent

## Expected behaviour per scenario

| # | Scenario | Rate counter | Block counter |
|---|---|---|---|
| 1 | No credentials, protected endpoint | ++ | ++ |
| 2 | Unknown Bearer token (not in DB as session key) | — | ++ |
| 3 | Valid, active Bearer session token | — | — |
| 4 | Expired Bearer session token | — | ++ |
| 5 | Revoked/used Bearer session token | — | ++ |
| 6 | `X-Api-Key` not found in DB | ++ | ++ |
| 7 | `X-Api-Key` valid, active | — | — |
| 8 | `X-Api-Key` expired | ++ | ++ |
| 9 | `X-Api-Key` revoked/used | ++ | ++ |

> `X-Api-Key` requests are not exempt from rate limiting: the counter increments
> only on auth failure, so a valid key (scenario 7) is never penalised while
> invalid/expired/revoked-key floods (6/8/9) are counted. Bearer/session-cookie
> requests remain exempt (scenarios 2–5) — those clients are still caught by the
> permanent block counter.
| 10 | `X-Api-Key` valid, wrong scope | — | — |
| 11 | No credentials, open-access GET | — | — |
