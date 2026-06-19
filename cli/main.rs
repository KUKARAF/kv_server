use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};

#[derive(Parser)]
#[command(name = "kv_cli", about = "KV Manager CLI — device-encrypted secret retrieval")]
struct Cli {
    #[arg(long, env = "KV_SERVER", default_value = "http://localhost:3000")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// First-time setup: generate X25519 keypair and register device
    Setup {
        /// Human-readable name for this device
        #[arg(long, default_value = "kv_cli")]
        name: String,
        /// Bearer token (approval-type, from admin panel Session → Device Token)
        #[arg(long, env = "KV_TOKEN")]
        token: String,
    },
    /// Fetch and decrypt a device-encrypted KV entry
    Get {
        /// Key name to retrieve
        key: String,
    },
    /// Check connectivity to the server
    Ping,
}

#[derive(Serialize, Deserialize)]
struct CliConfig {
    server_url: String,
    token: String,
    device_id: String,
    /// X25519 private key, base64-encoded (32 bytes)
    private_key: String,
}

#[derive(Deserialize)]
struct RegisterDeviceResponse {
    id: String,
}

#[derive(Deserialize)]
struct DeviceKvPayload {
    nonce: String,
    ciphertext: String,
    aad: String,
    recipient: Recipient,
}

#[derive(Deserialize)]
struct Recipient {
    ephemeral_pub: String,
    dek_nonce: String,
    encrypted_dek: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup { name, token } => cmd_setup(&cli.server, &name, &token).await?,
        Commands::Get { key } => cmd_get(&cli.server, &key).await?,
        Commands::Ping => cmd_ping(&cli.server).await?,
    }
    Ok(())
}

async fn cmd_setup(server: &str, name: &str, token: &str) -> anyhow::Result<()> {
    // Generate X25519 static keypair
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = X25519Pub::from(&priv_key);

    let pub_b64 = B64.encode(pub_key.as_bytes());
    let priv_b64 = B64.encode(priv_key.as_bytes());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(format!("{}/api/devices", server))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": name,
            "public_key": pub_b64,
            "key_type": "x25519",
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<RegisterDeviceResponse>()
        .await?;

    let config = CliConfig {
        server_url: server.to_string(),
        token: token.to_string(),
        device_id: resp.id.clone(),
        private_key: priv_b64,
    };
    save_config(&config)?;
    println!("✓ Device registered: {}", resp.id);
    println!("  Config saved to {}", config_path_display());
    Ok(())
}

async fn interactive_setup(server: &str) -> anyhow::Result<()> {
    use std::io::{self, BufRead, Write};
    eprintln!("No config found — running first-time setup.");
    eprint!("Device name [kv_cli]: ");
    io::stderr().flush()?;
    let mut name = String::new();
    io::stdin().lock().read_line(&mut name)?;
    let name = name.trim();
    let name = if name.is_empty() { "kv_cli" } else { name };

    let token = match std::env::var("KV_TOKEN") {
        Ok(t) if !t.is_empty() => {
            eprintln!("Using token from KV_TOKEN env var.");
            t
        }
        _ => {
            eprint!("Bearer token (admin → Session → Device Token): ");
            io::stderr().flush()?;
            let mut t = String::new();
            io::stdin().lock().read_line(&mut t)?;
            t.trim().to_string()
        }
    };
    if token.is_empty() {
        anyhow::bail!("token is required");
    }

    cmd_setup(server, name, &token).await
}

async fn cmd_get(server: &str, key: &str) -> anyhow::Result<()> {
    let config = match load_config() {
        Ok(c) => c,
        Err(_) => {
            interactive_setup(server).await?;
            eprintln!("Setup complete. Fetching key…");
            load_config()?
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let url = format!(
        "{}/api/admin/devices/{}/kv/{}",
        server, config.device_id, key
    );
    let payload: DeviceKvPayload = client
        .get(&url)
        .bearer_auth(&config.token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let plaintext = decrypt_payload(&config.private_key, &payload)?;
    println!("{}", plaintext);
    Ok(())
}

fn decrypt_payload(priv_b64: &str, payload: &DeviceKvPayload) -> anyhow::Result<String> {
    // Decode private key
    let priv_bytes: [u8; 32] = B64
        .decode(priv_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
    let priv_key = StaticSecret::from(priv_bytes);

    // Decode ephemeral public key
    let eph_bytes: [u8; 32] = B64
        .decode(&payload.recipient.ephemeral_pub)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ephemeral pubkey must be 32 bytes"))?;
    let eph_pub = X25519Pub::from(eph_bytes);

    // X25519 ECDH
    let shared = priv_key.diffie_hellman(&eph_pub);

    // HKDF-SHA256 → 32-byte wrap key
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(b"kv-device-wrap", &mut wrap_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    // AES-256-GCM decrypt DEK
    let dek_cipher = Aes256Gcm::new_from_slice(&wrap_key)?;
    let dek_nonce_bytes = B64.decode(&payload.recipient.dek_nonce)?;
    let dek_nonce = Nonce::from_slice(&dek_nonce_bytes);
    let encrypted_dek = B64.decode(&payload.recipient.encrypted_dek)?;
    let dek = dek_cipher
        .decrypt(dek_nonce, encrypted_dek.as_slice())
        .map_err(|_| anyhow::anyhow!("DEK decryption failed"))?;

    // AES-256-GCM decrypt body
    let body_cipher = Aes256Gcm::new_from_slice(&dek)?;
    let body_nonce_bytes = B64.decode(&payload.nonce)?;
    let body_nonce = Nonce::from_slice(&body_nonce_bytes);
    let ciphertext = B64.decode(&payload.ciphertext)?;
    let aad_bytes = B64.decode(&payload.aad)?;

    use aes_gcm::aead::Payload;
    let plaintext_bytes = body_cipher
        .decrypt(
            body_nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!("body decryption failed"))?;

    Ok(String::from_utf8(plaintext_bytes)?)
}

async fn cmd_ping(server: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client.get(format!("{}/health", server)).send().await?;
    if resp.status().is_success() {
        println!("✓ {} is reachable", server);
    } else {
        eprintln!("✗ {} returned {}", server, resp.status());
        std::process::exit(1);
    }
    Ok(())
}

fn config_path() -> anyhow::Result<std::path::PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("cannot find config dir"))?;
    Ok(base.join("kv_cli"))
}

fn config_path_display() -> String {
    config_path()
        .map(|p| p.join("config.toml").display().to_string())
        .unwrap_or_else(|_| "~/.config/kv_cli/config.toml".to_string())
}

fn save_config(config: &CliConfig) -> anyhow::Result<()> {
    let dir = config_path()?;
    std::fs::create_dir_all(&dir)?;
    let content = toml::to_string_pretty(config)?;
    std::fs::write(dir.join("config.toml"), content)?;
    Ok(())
}

fn load_config() -> anyhow::Result<CliConfig> {
    let path = config_path()?.join("config.toml");
    let content = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("no config found — run `kv_cli setup` first"))?;
    Ok(toml::from_str(&content)?)
}

fn print_qr(url: &str) {
    use qrcode::{render::unicode, QrCode};
    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .build();
            println!("{}", image);
        }
        Err(e) => {
            eprintln!("(QR code unavailable: {e})");
        }
    }
}

// Keep unused for future use
#[allow(dead_code)]
fn show_setup_qr(server: &str, token: &str) {
    let url = format!("kvsetup://{}?token={}", server, token);
    print_qr(&url);
}

/// Encrypt a value for multiple X25519 recipients (used for testing or future put command).
#[allow(dead_code)]
fn encrypt_for_recipients(
    value: &str,
    aad: &[u8],
    recipients: &[(String, [u8; 32])], // (device_id, pubkey_bytes)
) -> anyhow::Result<serde_json::Value> {
    use rand::RngCore;

    // Random DEK
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    // Encrypt body with DEK
    let body_cipher = Aes256Gcm::new_from_slice(&dek)?;
    let mut body_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut body_nonce_bytes);
    let body_nonce = Nonce::from_slice(&body_nonce_bytes);

    use aes_gcm::aead::Payload;
    let ciphertext = body_cipher
        .encrypt(body_nonce, Payload { msg: value.as_bytes(), aad })
        .map_err(|_| anyhow::anyhow!("body encryption failed"))?;

    // For each recipient, wrap DEK
    let mut recipient_list = Vec::new();
    for (device_id, pub_bytes) in recipients {
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519Pub::from(&eph_secret);
        let recipient_pub = X25519Pub::from(*pub_bytes);
        let shared = eph_secret.diffie_hellman(&recipient_pub);

        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_bytes());
        let mut wrap_key = [0u8; 32];
        hk.expand(b"kv-device-wrap", &mut wrap_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        let wrap_cipher = Aes256Gcm::new_from_slice(&wrap_key)?;
        let mut dek_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut dek_nonce_bytes);
        let dek_nonce = Nonce::from_slice(&dek_nonce_bytes);
        let encrypted_dek = wrap_cipher
            .encrypt(dek_nonce, dek.as_slice())
            .map_err(|_| anyhow::anyhow!("DEK encryption failed"))?;

        recipient_list.push(serde_json::json!({
            "device_id": device_id,
            "key_type": "x25519",
            "ephemeral_pub": B64.encode(eph_pub.as_bytes()),
            "dek_nonce": B64.encode(dek_nonce_bytes),
            "encrypted_dek": B64.encode(&encrypted_dek),
        }));
    }

    Ok(serde_json::json!({
        "nonce": B64.encode(body_nonce_bytes),
        "ciphertext": B64.encode(&ciphertext),
        "aad": B64.encode(aad),
        "recipients": recipient_list,
    }))
}
