# kv_manager

Production Rust/axum backend for **kv.osmosis.page** (SQLite). See `CLAUDE.md` for the
architecture overview, `DEPLOYMENT.md` for proxy / rate-limit / IP-trust details, and
`specs.md` for the request lifecycle.

## Reverse proxy (Caddy)

kv_manager must run behind a TLS-terminating reverse proxy that sets `X-Real-IP` — all
anti-abuse decisions derive the client IP from it (see `DEPLOYMENT.md`). The container
joins the external `caddy_proxy` network; the central Caddyfile routes the domain to it.

Baseline `kv.osmosis.page` site block:

```caddy
kv.osmosis.page {
    crowdsec
    import security_txt
    import honeytrap
    log {
        output file /var/log/caddy/access.log
        format json
    }
    reverse_proxy http://kv:3000 {
        header_up X-Real-IP {remote_host}
    }
}
```

### Serving the Android Digital Asset Links file

The Android client (`kv_apk`) performs its passkey (WebAuthn) device-enrolment ceremony
against RP id `kv.osmosis.page`. For Android Credential Manager to associate the app
(`dev.kv.apk`) with the domain, the platform fetches a Digital Asset Links statement at:

```
https://kv.osmosis.page/.well-known/assetlinks.json
```

Requirements are strict: it must live at **exactly that path on the RP domain**, return
**HTTP 200 with no redirect**, and be served as **`application/json`**. It contains only
public data (the app package name + the signing cert's SHA-256 fingerprint) — no secrets.

The file itself is versioned in the **static** repo at `public/kv/assetlinks.json`
(served at `static.osmosis.page/kv/assetlinks.json`), so it can change without rebuilding
this server. Caddy exposes it at the RP path by proxying that one path to the static
upstream — a transparent 200, **not** a redirect (Android does not follow redirects for
this fetch):

```caddy
kv.osmosis.page {
    crowdsec
    import security_txt
    import honeytrap
    log {
        output file /var/log/caddy/access.log
        format json
    }

    # Digital Asset Links for the kv_apk passkey ceremony. Must be 200 (no redirect),
    # application/json, at exactly this path. The file is hosted in the static site;
    # 192.168.1.66:8081 is the same upstream the static.osmosis.page block uses.
    handle /.well-known/assetlinks.json {
        rewrite * /kv/assetlinks.json
        header Content-Type application/json
        reverse_proxy http://192.168.1.66:8081
    }

    # Everything else → the app.
    handle {
        reverse_proxy http://kv:3000 {
            header_up X-Real-IP {remote_host}
        }
    }
}
```

Note the structure change: once any `handle` block is used, the app's `reverse_proxy`
must move into its own catch-all `handle { … }` so the two are mutually exclusive and the
specific `/.well-known/assetlinks.json` path is matched first.

This is only needed if the Android app performs passkeys itself. If enrolment is done
exclusively through the web admin panel (which does the passkey touch in-browser and needs
no asset links), this block can be omitted. The paired server-side requirement — accepting
the `android:apk-key-hash:<…>` origin in the WebAuthn config — is tracked separately.
