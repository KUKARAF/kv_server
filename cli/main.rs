use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "kv_cli", about = "KV Manager CLI")]
struct Cli {
    #[arg(long, env = "KV_SERVER", default_value = "http://localhost:3000")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate this device and obtain an API key
    Auth {
        #[arg(long, default_value = "kv_cli device")]
        label: String,
    },
    /// Check connectivity to the server
    Ping,
}

#[derive(Serialize, Deserialize)]
struct CliConfig {
    server_url: String,
    api_key: String,
}

#[derive(Deserialize)]
struct CreateDeviceAuthResponse {
    id: String,
    url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct PollStatusResponse {
    status: String,
    api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Auth { label } => cmd_auth(&cli.server, &label).await?,
        Commands::Ping => cmd_ping(&cli.server).await?,
    }
    Ok(())
}

async fn cmd_auth(server: &str, label: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(format!("{}/api/device-auth", server))
        .json(&serde_json::json!({ "label": label }))
        .send()
        .await?
        .error_for_status()?
        .json::<CreateDeviceAuthResponse>()
        .await?;

    println!("Open this URL in your browser to approve this device:");
    println!();
    println!("  {}", resp.url);
    println!();
    print_qr(&resp.url);
    println!();
    println!("Expires at: {}", resp.expires_at);
    println!("Waiting for admin approval... (Ctrl+C to cancel)");
    println!();

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let poll = match client
            .get(format!("{}/api/device-auth/{}/status", server, resp.id))
            .send()
            .await
        {
            Ok(r) => match r.error_for_status() {
                Ok(r) => match r.json::<PollStatusResponse>().await {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Warning: failed to parse poll response: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    eprintln!("Warning: poll request failed: {e}");
                    continue;
                }
            },
            Err(e) => {
                eprintln!("Warning: network error: {e}");
                continue;
            }
        };

        match poll.status.as_str() {
            "pending" => continue,
            "approved" => {
                let key = poll
                    .api_key
                    .ok_or_else(|| anyhow::anyhow!("server approved but sent no key"))?;
                save_config(server, &key)?;
                println!("✓ Approved! API key saved to {}", config_path_display());
                return Ok(());
            }
            "rejected" => {
                eprintln!("✗ Request rejected by admin.");
                std::process::exit(1);
            }
            "expired" => {
                eprintln!("✗ Request expired. Run `kv_cli auth` again.");
                std::process::exit(1);
            }
            other => {
                eprintln!("✗ Unexpected status: {other}");
                std::process::exit(1);
            }
        }
    }
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

fn config_path() -> anyhow::Result<std::path::PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("cannot find config dir"))?;
    Ok(base.join("kv_cli"))
}

fn config_path_display() -> String {
    config_path()
        .map(|p| p.join("config.toml").display().to_string())
        .unwrap_or_else(|_| "~/.config/kv_cli/config.toml".to_string())
}

fn save_config(server_url: &str, api_key: &str) -> anyhow::Result<()> {
    let dir = config_path()?;
    std::fs::create_dir_all(&dir)?;
    let config = CliConfig {
        server_url: server_url.to_string(),
        api_key: api_key.to_string(),
    };
    let content = toml::to_string_pretty(&config)?;
    std::fs::write(dir.join("config.toml"), content)?;
    Ok(())
}
