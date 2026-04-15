fn main() {
    // Embed VERSION (major.minor.shortsha) at compile time.
    // Set by the Docker build-arg → ENV VERSION=... in the Dockerfile.
    // Falls back to "dev" for local builds outside CI.
    let version = std::env::var("VERSION").unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=APP_VERSION={version}");
    println!("cargo:rerun-if-env-changed=VERSION");

    // Generate EMOJI_POOL from admin/emoji.json (single source of truth).
    // Refresh the file with: .tools/get_emojis.sh admin/emoji.json
    println!("cargo:rerun-if-changed=admin/emoji.json");
    let json_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("admin/emoji.json");
    let data = std::fs::read_to_string(&json_path).expect("admin/emoji.json missing — run .tools/get_emojis.sh admin/emoji.json");
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data).expect("parse admin/emoji.json");
    let pool: Vec<String> = entries
        .iter()
        .filter_map(|v| v["e"].as_str())
        .map(|s| format!("    {:?}", s))
        .collect();
    let code = format!(
        "pub const EMOJI_POOL: &[&str] = &[\n{}\n];\n",
        pool.join(",\n")
    );
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out).join("emoji_pool.rs"), code)
        .expect("write emoji_pool.rs");
}
