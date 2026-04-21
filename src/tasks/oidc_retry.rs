use crate::{auth::oidc::init_client, state::AppState};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Retries OIDC discovery in the background until it succeeds.
/// Exits once the client is initialized.
pub async fn run(state: Arc<AppState>) {
    loop {
        sleep(RETRY_INTERVAL).await;

        if state.oidc_client.read().await.is_some() {
            return;
        }

        tracing::info!("OIDC not initialized, retrying discovery...");
        match init_client(
            &state.config.oidc_issuer_url,
            &state.config.oidc_client_id,
            &state.config.oidc_client_secret,
            &state.config.oidc_redirect_uri,
        )
        .await
        {
            Ok(client) => {
                *state.oidc_client.write().await = Some(client);
                tracing::info!("OIDC initialized successfully (retry succeeded)");
                return;
            }
            Err(e) => {
                tracing::warn!("OIDC retry failed, will try again in {}s: {e:#}", RETRY_INTERVAL.as_secs());
            }
        }
    }
}
