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
