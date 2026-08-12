//! Server-side device-wrap for session tokens.
//!
//! This produces the **exact same envelope** the `devices/` module stores and the
//! `kv_cli` / `kv_apk` clients already decrypt with (see `kv_cli/src/crypto.rs`
//! `decrypt_device_kv`): X25519/P256 ECDH → HKDF-SHA256(salt = 32×0x00,
//! info = `kv-device-wrap`) → AES-256-GCM DEK wrap + AES-256-GCM body. It must stay
//! byte-compatible with that scheme — do not change the KDF salt/info or the AEAD.
//!
//! Used at session-request approval time so an approved session token is delivered
//! ECDH-wrapped to a registered device's public key and is unusable without that
//! device's private key.

// generic-array 0.14 (pulled in transitively by aes-gcm/aead/hkdf) marks its entire
// crate `#[deprecated]` on rustc >= 1.65; every Key::from_slice/Nonce::from_slice call
// below trips it. Same situation as kv_cli/src/crypto.rs — the crate self-deprecates;
// fixing it for real is a coordinated aes-gcm/aead/hkdf bump, deferred, not a local fix.
#![allow(deprecated)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

/// The device-KV envelope: an AES-256-GCM body plus a single recipient's ECDH-wrapped DEK.
/// Every field is base64 (STANDARD), matching what the clients decode.
pub struct Envelope {
    pub key_type: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

/// Wrap `plaintext` for a single device. `public_key_b64` is the device's registered
/// public key (raw 32-byte X25519, or DER-encoded P-256), `key_type` is `"x25519"` or
/// `"p256"`, and `aad` is authenticated (not encrypted) associated data bound into the
/// body — callers pass the session-request id to bind the ciphertext to the request.
pub fn wrap_for_device(
    key_type: &str,
    public_key_b64: &str,
    aad: &str,
    plaintext: &[u8],
) -> Result<Envelope> {
    let mut rng = OsRng;

    let mut dek: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *dek);

    let mut body_nonce = [0u8; 12];
    rng.fill_bytes(&mut body_nonce);

    let aad_bytes = aad.as_bytes();

    let body_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*dek));
    let ciphertext = body_cipher
        .encrypt(
            Nonce::from_slice(&body_nonce),
            Payload {
                msg: plaintext,
                aad: aad_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!("body encryption failed"))?;

    let pub_bytes = B64
        .decode(public_key_b64)
        .context("invalid device public key")?;
    let (eph_pub_bytes, shared_bytes) = match key_type {
        "x25519" => wrap_x25519(&pub_bytes)?,
        "p256" => wrap_p256(&pub_bytes)?,
        other => anyhow::bail!("unsupported key type: {other}"),
    };
    let shared_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(shared_bytes);

    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared_bytes);
    let mut wrap_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    hk.expand(b"kv-device-wrap", &mut *wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let mut dek_nonce = [0u8; 12];
    rng.fill_bytes(&mut dek_nonce);

    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrap_key));
    let encrypted_dek = wrap_cipher
        .encrypt(Nonce::from_slice(&dek_nonce), dek.as_ref())
        .map_err(|_| anyhow::anyhow!("DEK encryption failed"))?;

    Ok(Envelope {
        key_type: key_type.to_string(),
        nonce: B64.encode(body_nonce),
        ciphertext: B64.encode(&ciphertext),
        aad: B64.encode(aad_bytes),
        ephemeral_pub: B64.encode(&eph_pub_bytes),
        dek_nonce: B64.encode(dek_nonce),
        encrypted_dek: B64.encode(&encrypted_dek),
    })
}

fn wrap_x25519(pub_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 public key must be 32 bytes"))?;
    let device_pub = PublicKey::from(arr);
    let ephemeral = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&device_pub);
    Ok((eph_pub.as_bytes().to_vec(), shared.as_bytes().to_vec()))
}

fn wrap_p256(pub_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePublicKey;
    let device_pub = p256::PublicKey::from_public_key_der(pub_bytes)
        .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {e}"))?;
    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let eph_pub = ephemeral.public_key();
    let shared = ephemeral.diffie_hellman(&device_pub);
    let eph_pub_bytes = eph_pub.to_encoded_point(false).as_bytes().to_vec();
    Ok((eph_pub_bytes, shared.raw_secret_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePublicKey;
    use x25519_dalek::StaticSecret;

    /// Mirror of the clients' `decrypt_device_kv` unwrap path, used only to prove the
    /// envelope this module produces round-trips through the exact scheme the clients use.
    fn unwrap(
        shared: &[u8],
        dek_nonce_b64: &str,
        encrypted_dek_b64: &str,
        nonce_b64: &str,
        ciphertext_b64: &str,
        aad_b64: &str,
    ) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"kv-device-wrap", &mut wrap_key).unwrap();
        let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let dek = wrap_cipher
            .decrypt(
                Nonce::from_slice(&B64.decode(dek_nonce_b64).unwrap()),
                B64.decode(encrypted_dek_b64).unwrap().as_ref(),
            )
            .unwrap();
        let body_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        body_cipher
            .decrypt(
                Nonce::from_slice(&B64.decode(nonce_b64).unwrap()),
                Payload {
                    msg: &B64.decode(ciphertext_b64).unwrap(),
                    aad: &B64.decode(aad_b64).unwrap(),
                },
            )
            .unwrap()
    }

    #[test]
    fn x25519_roundtrip() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let pub_b64 = B64.encode(public.as_bytes());

        let token = b"session-token-abc123";
        let env = wrap_for_device("x25519", &pub_b64, "req-id-1", token).unwrap();

        let eph: [u8; 32] = B64.decode(&env.ephemeral_pub).unwrap().try_into().unwrap();
        let shared = secret.diffie_hellman(&PublicKey::from(eph));
        let out = unwrap(
            shared.as_bytes(),
            &env.dek_nonce,
            &env.encrypted_dek,
            &env.nonce,
            &env.ciphertext,
            &env.aad,
        );
        assert_eq!(out, token);
    }

    #[test]
    fn p256_roundtrip() {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        let pub_der = public.to_public_key_der().unwrap();
        let pub_b64 = B64.encode(pub_der.as_bytes());

        let token = b"session-token-xyz789";
        let env = wrap_for_device("p256", &pub_b64, "req-id-2", token).unwrap();

        let eph_pt =
            p256::EncodedPoint::from_bytes(B64.decode(&env.ephemeral_pub).unwrap()).unwrap();
        let eph_pub = p256::PublicKey::from_encoded_point(&eph_pt).unwrap();
        let shared = secret.diffie_hellman(&eph_pub);
        let out = unwrap(
            shared.raw_secret_bytes().as_slice(),
            &env.dek_nonce,
            &env.encrypted_dek,
            &env.nonce,
            &env.ciphertext,
            &env.aad,
        );
        assert_eq!(out, token);
    }

    #[test]
    fn unsupported_key_type_errors() {
        assert!(wrap_for_device("rsa", "AAAA", "aad", b"x").is_err());
    }
}
