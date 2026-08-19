#!/usr/bin/env bash
# Adversarial code-review pre-commit gate for the two device/session enrollment
# trust boundaries. Runs headless Claude Code as a static reviewer (no live
# server, no browser) against the current on-disk state of the relevant files
# and fails the commit if either reviewer's verdict is FAIL.
set -euo pipefail
cd "$(dirname "$0")/.."

DEVICE_FILES="src/devices/handlers.rs src/devices/model.rs src/devices/mod.rs src/webauthn/handlers.rs src/webauthn/mod.rs admin/device-proposal.html admin/device-registration.html admin/js/utils.js"
SESSION_FILES="src/session_request/handlers.rs src/session_request/model.rs src/session_request/mod.rs admin/session-request.html admin/dashboard.html"

run_review() {
  local name="$1" files="$2" prompt="$3"
  echo "== security-review: ${name} =="
  local out
  out=$(claude -p "$prompt" \
    --allowedTools "Read Grep Glob" \
    --add-dir "$(pwd)" \
    2>&1) || {
    echo "$out"
    echo "security-review: ${name}: claude invocation failed" >&2
    return 2
  }
  echo "$out"
  local verdict
  verdict=$(printf '%s\n' "$out" | grep -o 'VERDICT:.*' | tail -n1)
  if [[ -z "$verdict" ]]; then
    echo "security-review: ${name}: no VERDICT line found in reviewer output" >&2
    return 2
  fi
  if [[ "$verdict" == VERDICT:\ FAIL* ]]; then
    echo "security-review: ${name}: ${verdict}" >&2
    return 1
  fi
  echo "security-review: ${name}: ${verdict}"
  return 0
}

DEVICE_PROMPT="You are doing an adversarial security review of the device-enrollment
confirmation flow in this repo (kv_manager, Rust/axum server + static admin HTML/JS).

Read these files: ${DEVICE_FILES}

Threat model: could an attacker get a device enrolled into the system by timing
things so a legitimate admin ends up confirming an attacker-controlled device,
WITHOUT that confirmation being backed by a genuine, server-verified WebAuthn
ceremony (a real physical passkey touch, verified server-side against a
server-issued single-use challenge)? Specifically check:

- Does the confirm button actually drive a real WebAuthn ceremony
  (navigator.credentials.create/get via the webauthn library), or could the
  server-side 'link' step accept a client-asserted success with no server-side
  attestation/assertion verification?
- Is the resulting device_id derived only from a server-side-verified
  registration result — never from anything the client could put in a request
  body unchecked?
- Is the WebAuthn challenge itself server-generated, single-use, and bound to
  this specific registration ceremony (not reusable/predictable)?

If ANY of these can be bypassed — i.e. a device could become usable
('confirmed'/registered) without a genuine, server-verified WebAuthn ceremony —
this is a FAIL. Do not flag things that are merely inconvenient or that rely on
the admin visually comparing text; the question is strictly about whether the
server can be fooled into accepting an unverified registration.

End your entire response with exactly one line, nothing after it:
VERDICT: PASS
or
VERDICT: FAIL: <one sentence reason, citing the file/function>"

SESSION_PROMPT="You are doing an adversarial security review of the session-request
approval flow in this repo (kv_manager, Rust/axum server + static admin HTML/JS).

Read these files: ${SESSION_FILES}

The project owner has stated this explicit, non-negotiable rule (quoted
verbatim): 'irrelevant how many please-check-this text/token/key hints are on
the screen — if the admin is able to press Approve and is NOT required to
first obtain a token from a URL (delivered out-of-band, e.g. shown only by the
requesting device itself, not derivable from the approval page alone), this is
a FAILURE.' A device name or 'claims to be' label rendered on the approval
page, even if it is cryptographically bound to the real device via a
challenge-response mechanism elsewhere in the system, does NOT satisfy this
rule by itself — the rule specifically requires an explicit step where the
admin must fetch/enter a token obtained from a URL before Approve can succeed.

Trace the actual approve flow end to end: what, if anything, does the admin's
browser require — beyond opening the approval link and clicking Approve —
before POST .../approve succeeds? Is there any point where the admin must
retrieve a token/code from a URL and supply it back to the server as part of
approving?

If Approve can succeed with nothing beyond visiting the approval link and
clicking Approve (i.e. no separate token-from-a-url step is required), this is
a FAIL per the owner's stated rule, even if you believe the existing
device-identity/challenge-response design is cryptographically sound on other
grounds — that argument does not satisfy this specific rule and should not
change the verdict.

End your entire response with exactly one line, nothing after it:
VERDICT: PASS
or
VERDICT: FAIL: <one sentence reason, citing the file/function>"

status=0
run_review "device-enrollment-mitm" "$DEVICE_FILES" "$DEVICE_PROMPT" || status=1
run_review "session-approval-mitm" "$SESSION_FILES" "$SESSION_PROMPT" || status=1

exit "$status"
