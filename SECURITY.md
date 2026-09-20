# Security

## Agent access to management-key functionality — 2026-09-20

This note documents an incident in which an automated coding agent reached
management-key (`mgmt-key`) functionality served by this manager/server through
the `kv` CLI, using an already-valid on-device session. It is recorded here to
motivate server-side hardening. Please read it accurately — no secret material
was exfiltrated.

### What happened

- An automated coding agent (Claude Code) running as the local user, on a
  workstation that already held a valid `kv` session bound to a registered
  device, was asked to provision an OpenRouter provider key for application
  testing.
- The client issued `kv mgmt-key list`. The server returned management-key
  **record metadata only** — id, provider, label, status, created / last-used
  timestamps, and default limits. One record surfaced was an `openrouter`
  provider management key. This is metadata, **not** the secret key material.
- The client issued `kv mgmt-key keys list <mgmt_key_id>`, which the server
  answered with HTTP 404.
- No `keys create`, `keys show`, or content-reveal request was made. **No
  provider key was provisioned, and no raw management-key or provider-key secret
  was returned by the server.**

### The access vector (server side)

- The device holds `device.key` plus an unexpired session token; the session
  validated as active and bound to a registered device. From the server's
  perspective, that standing session authorized the full `mgmt-key` surface
  (`list`, `keys create`, `keys show`, `keys rotate`, `revoke`) with **no
  additional human-in-the-loop check**.
- Any local process on that workstation — including an autonomous agent — can
  therefore present a valid session and exercise management-key operations. The
  server does not currently distinguish an interactive human request from a
  non-interactive / agent-driven one, and does not require a fresh approval for
  privileged `mgmt-key` operations beyond the standing session.
- The management key material itself remains encrypted at rest and is only
  decrypted server-side to call the provider, so it was never disclosed — but a
  request carrying a valid session is nonetheless sufficient to have the server
  provision or reveal provider keys.

### Recommended hardening (server side)

1. Require an out-of-band human approval (for example via the kv approver app /
   push flow already present in this server) before honoring privileged
   `mgmt-key` operations — `keys create`, `keys show`/content reveal, and
   `keys rotate` — rather than treating a passive standing session as
   sufficient authorization.
2. Scope sessions so that `mgmt-key` subcommands demand re-authentication or a
   step-up factor; keep general sessions short-lived and require an elevated,
   short-lived grant specifically for management-key endpoints.
3. Do not rely on the client's agent-detection guard (which is client-side and
   self-overridable). Enforce the reveal / provisioning policy on the server:
   require interactive confirmation or a second factor before the server will
   return raw key content.
4. Audit-log every `mgmt-key` endpoint call (`list`, `create`, `show`,
   `rotate`, `revoke`) with device, session, and outcome, and alert on
   non-interactive / agent-pattern access (for example a burst of `mgmt-key`
   calls without an accompanying approval event).
5. Treat device-key possession as insufficient on its own for the most
   privileged operations; pair it with an approval or step-up check server-side.

### Follow-up

The management key involved (OpenRouter) is being rotated as a precaution,
independent of the fact that no secret was disclosed.
