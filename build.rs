fn main() {
    // Embed VERSION (major.minor.shortsha) at compile time.
    // Set by the Docker build-arg → ENV VERSION=... in the Dockerfile.
    // Falls back to "dev" for local builds outside CI.
    let version = std::env::var("VERSION").unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=APP_VERSION={version}");
    println!("cargo:rerun-if-env-changed=VERSION");
}
