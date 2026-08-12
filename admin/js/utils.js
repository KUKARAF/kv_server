// Shared helpers used across all admin pages.

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/** Decode a base64url string to ArrayBuffer */
function b64decode(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    s.length + (4 - (s.length % 4)) % 4, '='
  );
  const bin = atob(padded);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

/** Encode ArrayBuffer, Uint8Array, or TypedArray to base64url */
function b64encode(buf) {
  const bytes = buf instanceof Uint8Array
    ? buf
    : new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ── WebAuthn-gated device enrolment ──────────────────────────────────────────
// Registering a device is a two-step ceremony bound to a passkey touch: begin returns
// a WebAuthn authentication challenge, the browser signs it, and finish verifies the
// assertion server-side before the device is stored. A stolen OIDC session alone can't
// enrol a device. Returns the created device record ({ id }); throws Error with a
// user-facing message on failure.
async function enrolDevice(name, publicKeyB64, keyType) {
  const beginResp = await fetch('/api/devices/register/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, public_key: publicKeyB64, key_type: keyType }),
  });
  if (!beginResp.ok) {
    if (beginResp.status === 409) {
      throw new Error(`A device named "${name}" is already registered. Choose a different name or delete the existing device first.`);
    }
    const err = await beginResp.json().catch(() => null);
    if (beginResp.status === 403) {
      throw new Error(err?.error || 'Register a hardware key first (Zero Trust → Register key) before enrolling a device.');
    }
    throw new Error(err?.error || 'Enrolment could not start (error ' + beginResp.status + ').');
  }
  const { challenge_id, options } = await beginResp.json();

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: _decodeWebAuthnGetOptions(options.publicKey) });
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      throw new Error('Passkey confirmation was cancelled or timed out.');
    }
    throw e;
  }

  const finishResp = await fetch('/api/devices/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id, assertion: _serializeAssertion(assertion) }),
  });
  if (!finishResp.ok) {
    if (finishResp.status === 409) {
      throw new Error(`A device named "${name}" is already registered.`);
    }
    const err = await finishResp.json().catch(() => null);
    throw new Error(err?.error || 'Passkey verification failed (error ' + finishResp.status + ').');
  }
  return await finishResp.json();
}

/** Decode a WebAuthn get() options object: base64url fields → ArrayBuffer. */
function _decodeWebAuthnGetOptions(pk) {
  const out = { ...pk };
  if (pk.challenge) out.challenge = b64decode(pk.challenge);
  if (pk.allowCredentials) {
    out.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64decode(c.id) }));
  }
  return out;
}

/** Serialize a PublicKeyCredential assertion to the JSON webauthn-rs expects at finish. */
function _serializeAssertion(cred) {
  const resp = cred.response;
  return {
    id: cred.id,
    rawId: b64encode(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults(),
    response: {
      authenticatorData: b64encode(resp.authenticatorData),
      clientDataJSON: b64encode(resp.clientDataJSON),
      signature: b64encode(resp.signature),
      userHandle: resp.userHandle ? b64encode(resp.userHandle) : null,
    },
  };
}
