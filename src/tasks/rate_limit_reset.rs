use crate::state::AppState;
use chrono::{Timelike, Utc};
use std::sync::Arc;

pub async fn run(state: Arc<AppState>) {
    loop {
        let now = Utc::now();
        // Calculate seconds until next midnight UTC
        let seconds_until_midnight = 86400
            - (now.num_seconds_from_midnight() as i64);
        let sleep_secs = seconds_until_midnight.max(1) as u64;

        tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;

        let count = state.rate_counters.len();
        state.rate_counters.clear();
        tracing::info!(cleared_ips = count, "rate limit counters reset");

        // Sleep 1 second to avoid double-firing at midnight boundary
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
