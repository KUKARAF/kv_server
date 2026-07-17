# Deployment

## Reverse proxy is mandatory

kv_manager derives the client IP for all anti-abuse decisions from `X-Real-IP`,
which it trusts only when `TRUST_PROXY_HEADERS=true` (the default). Run it behind
a proxy that terminates TLS and sets `X-Real-IP` to the true client address, and
ensure the app's `LISTEN_ADDR` is **not** reachable directly (bind loopback or a
private network). If the app is ever exposed directly, set
`TRUST_PROXY_HEADERS=false` so it uses the socket peer instead of a spoofable
header.

## Anti-abuse: what the app does and does not do

The in-app protection is **failure-based only**:

- **Failure counter** (`DAILY_RATE_LIMIT`, default 1000): per-IP count of *auth
  failures*, reset at midnight UTC. Successful and open-access requests never
  count. This is **not** a throughput limit.
- **Escalating blocks** (`AUTH_FAILURE_THRESHOLD`, default 10): after N failures
  an IP is blocked for `AUTH_BLOCK_BASE_SECS` (default 1h), doubling per repeat
  offense up to 30 days, then auto-expiring. IPv6 is bucketed to /64. Manual
  permanent blocks (via the admin UI / a row with `blocked_at` set and
  `unblock_at` NULL) are preserved.

There is deliberately **no cap on the volume of successful/valid traffic** — a
client with valid credentials can make unlimited requests. Protecting raw
request *capacity* (flood / L7 DoS) is the proxy's job.

## Recommended Caddy volume limit

Using the [`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) module,
cap total requests per client IP in front of the app:

```caddy
kv.example.com {
    rate_limit {
        zone kv_volume {
            key    {remote_host}
            events 600
            window 1m
        }
    }

    reverse_proxy 127.0.0.1:3000 {
        header_up X-Real-IP {remote_host}
    }
}
```

`600 events / 1m` is a generous per-IP ceiling that stops runaway floods while
leaving normal API use untouched — tune to your traffic. The `header_up X-Real-IP`
line is what the app's anti-abuse logic keys on; keep it in sync with the proxy's
real client address.
