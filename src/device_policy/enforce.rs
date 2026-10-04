//! Enforcement of per-device key policies and device bans.
//!
//! Every device-attributable request runs `ensure_not_banned`; every device-attributable
//! read of a specific KV entry value runs `authorize_key` (ban check + policy check, and on
//! violation: escalating ban + notification). Both reject with `AppError::DeviceBanned`,
//! which carries no `AuthFailed` marker — a policy violation is not an authentication
//! failure and must move neither per-IP counter (expected_behaviour_for_tests.md).

use crate::{
    auth::middleware::SessionClaims,
    device_policy::model::{PolicyMode, MAX_PATTERN_LEN},
    error::AppError,
    notify,
    state::AppState,
};
use regex::{Regex, RegexBuilder};
use sqlx::{SqliteExecutor, SqlitePool};
use std::net::IpAddr;

/// Cap on any single device ban: 30 days (same cap as IP blocks).
const MAX_BAN_SECS: u64 = 30 * 24 * 3600;
/// Compiled-program size limit for policy regexes.
const REGEX_SIZE_LIMIT: usize = 1 << 16;

/// A device's stored policy.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub mode: PolicyMode,
    pub keys: Vec<String>,
    pub pattern: Option<String>,
}

/// Compile a policy pattern so it must match the WHOLE key name. Used both to validate on
/// save and to evaluate at request time.
pub fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    if pattern.chars().count() > MAX_PATTERN_LEN {
        return Err(format!("pattern exceeds {MAX_PATTERN_LEN} characters"));
    }
    RegexBuilder::new(&format!("^(?:{pattern})$"))
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => "pattern is too complex".to_string(),
            _ => "invalid regex pattern".to_string(),
        })
}

/// Pure policy decision. A regex policy whose pattern is missing or no longer compiles
/// fails closed (denies).
pub fn policy_allows(
    mode: PolicyMode,
    keys: &[String],
    pattern: Option<&str>,
    kv_key: &str,
) -> bool {
    match mode {
        PolicyMode::AllowAll => true,
        PolicyMode::AllowList => keys.iter().any(|k| k == kv_key),
        PolicyMode::DenyList => !keys.iter().any(|k| k == kv_key),
        PolicyMode::Regex => pattern
            .and_then(|p| compile_pattern(p).ok())
            .is_some_and(|re| re.is_match(kv_key)),
    }
}

/// nth ban (1-based) lasts `base * 2^(n-1)`, capped at 30 days. Mirrors ip_block maths.
pub fn ban_duration_secs(base_secs: u64, nth: i64) -> u64 {
    let shift = (nth.saturating_sub(1)).clamp(0, 40) as u32;
    base_secs.saturating_mul(1u64 << shift).min(MAX_BAN_SECS)
}

/// Rejects with `DeviceBanned` while the device has an unexpired ban. One PK lookup.
/// Generic over the executor so callers holding a transaction can pass `&mut *tx`.
pub async fn ensure_not_banned<'e, E>(exec: E, device_id: &str) -> Result<(), AppError>
where
    E: SqliteExecutor<'e>,
{
    let banned = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM device_bans
           WHERE device_id = ? AND banned_at IS NOT NULL
             AND unban_at IS NOT NULL AND unban_at > datetime('now')"#,
        device_id
    )
    .fetch_optional(exec)
    .await?
    .is_some();

    if banned {
        tracing::warn!(device_id = %device_id, "banned device rejected");
        return Err(AppError::DeviceBanned);
    }
    Ok(())
}

/// Loads a device's policy; `None` = no row = allow_all.
pub async fn load_policy(
    pool: &SqlitePool,
    device_id: &str,
) -> Result<Option<LoadedPolicy>, AppError> {
    let row = sqlx::query!(
        "SELECT mode, pattern FROM device_policies WHERE device_id = ?",
        device_id
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    // An unknown mode can't be stored (CHECK constraint); treat it as maximally
    // restrictive rather than trusting it.
    let mode = PolicyMode::parse(&row.mode).unwrap_or(PolicyMode::AllowList);

    let keys = match mode {
        PolicyMode::AllowList | PolicyMode::DenyList => {
            sqlx::query_scalar!(
                "SELECT kv_key FROM device_policy_keys WHERE device_id = ?",
                device_id
            )
            .fetch_all(pool)
            .await?
        }
        PolicyMode::AllowAll | PolicyMode::Regex => Vec::new(),
    };

    Ok(Some(LoadedPolicy {
        mode,
        keys,
        pattern: row.pattern,
    }))
}

/// True when the device has any policy other than allow_all.
pub async fn is_restricted(pool: &SqlitePool, device_id: &str) -> Result<bool, AppError> {
    Ok(load_policy(pool, device_id)
        .await?
        .is_some_and(|p| p.mode != PolicyMode::AllowAll))
}

/// Pure policy lookup for `device_id` and `kv_key` (no ban check, no side effects).
pub async fn key_permitted(
    pool: &SqlitePool,
    device_id: &str,
    kv_key: &str,
) -> Result<bool, AppError> {
    Ok(match load_policy(pool, device_id).await? {
        None => true,
        Some(p) => policy_allows(p.mode, &p.keys, p.pattern.as_deref(), kv_key),
    })
}

/// A restricted device-bound session must not be able to mint fresh credentials (API keys,
/// CLI/approval tokens, session keys) or obtain management-key material: those are not
/// device-bound and would let it sidestep its own policy. Plain 403, no ban — it is not a
/// KV read. Unrestricted (allow_all / no policy) devices and non-device sessions pass.
pub async fn ensure_may_mint_credentials(
    pool: &SqlitePool,
    claims: &SessionClaims,
) -> Result<(), AppError> {
    if let Some(device_id) = claims.device_id.as_deref() {
        if is_restricted(pool, device_id).await? {
            return Err(AppError::Forbidden(
                "not permitted for this device".to_string(),
            ));
        }
    }
    Ok(())
}

/// Ban check, then policy check for a device-attributable read of `kv_key`. On violation
/// records an escalating ban, fires a notification and returns `DeviceBanned`.
pub async fn authorize_key(
    state: &AppState,
    device_id: &str,
    owner_id: &str,
    kv_key: &str,
    ip: Option<IpAddr>,
) -> Result<(), AppError> {
    ensure_not_banned(&state.pool, device_id).await?;

    if key_permitted(&state.pool, device_id, kv_key).await? {
        return Ok(());
    }

    record_violation(state, device_id, owner_id, kv_key, ip).await?;
    Err(AppError::DeviceBanned)
}

async fn record_violation(
    state: &AppState,
    device_id: &str,
    owner_id: &str,
    kv_key: &str,
    ip: Option<IpAddr>,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let ip_str = ip.map(|i| i.to_string());

    sqlx::query!(
        "INSERT INTO device_bans (device_id, owner_id, ban_count) VALUES (?, ?, 0)
         ON CONFLICT(device_id) DO NOTHING",
        device_id,
        owner_id
    )
    .execute(pool)
    .await?;

    let row = sqlx::query!(
        r#"SELECT ban_count,
                  (banned_at IS NOT NULL AND unban_at IS NOT NULL
                   AND unban_at > datetime('now')) as "active!: bool"
           FROM device_bans WHERE device_id = ?"#,
        device_id
    )
    .fetch_one(pool)
    .await?;

    // A concurrent violation already applied the ban — don't escalate twice.
    if row.active {
        return Ok(());
    }

    let new_count = row.ban_count.saturating_add(1);
    let secs = ban_duration_secs(state.config.device_ban_base_secs, new_count);
    let modifier = format!("+{secs} seconds");

    // Guarded on the old count: if a racing request got here first, it owns the ban.
    let applied = sqlx::query!(
        "UPDATE device_bans
         SET banned_at = datetime('now'),
             unban_at  = datetime('now', ?),
             ban_count = ?,
             last_key  = ?,
             last_ip   = ?
         WHERE device_id = ? AND ban_count = ?",
        modifier,
        new_count,
        kv_key,
        ip_str,
        device_id,
        row.ban_count
    )
    .execute(pool)
    .await?
    .rows_affected();

    if applied == 0 {
        return Ok(());
    }

    let device_name = sqlx::query_scalar!("SELECT name FROM devices WHERE id = ?", device_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| device_id.to_string());

    tracing::warn!(
        device_id = %device_id,
        kv_key = %kv_key,
        ban_count = new_count,
        secs,
        "device banned for key policy violation"
    );
    // Names only — never a KV value.
    notify::send(
        pool.clone(),
        format!(
            "kv-manager: device {device_name} banned for {secs}s (offense #{new_count}): requested {kv_key}, which its key policy does not allow"
        ),
        "high",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// (mode, keys, pattern, requested key, expected)
    type Case<'a> = (PolicyMode, &'a [String], Option<&'a str>, &'a str, bool);

    #[test]
    fn policy_allows_table() {
        use PolicyMode::*;
        let list = k(&["OPENROUTER_API_KEY", "FOO"]);
        let cases: &[Case] = &[
            (AllowAll, &[], None, "ANYTHING", true),
            (AllowList, &list, None, "OPENROUTER_API_KEY", true),
            (AllowList, &list, None, "FOO_BAR", false),
            (AllowList, &[], None, "FOO", false),
            (DenyList, &list, None, "FOO", false),
            (DenyList, &list, None, "BAR", true),
            (DenyList, &[], None, "BAR", true),
            (Regex, &[], Some("FOO"), "FOO", true),
            // Anchoring: a bare pattern must match the whole key name.
            (Regex, &[], Some("FOO"), "FOO_BAR", false),
            (Regex, &[], Some("FOO"), "XFOO", false),
            (Regex, &[], Some("OPENAI_.*"), "OPENAI_KEY", true),
            (Regex, &[], Some("OPENAI_.*"), "MY_OPENAI_KEY", false),
            // Alternation must not escape the anchors.
            (Regex, &[], Some("A|B"), "A", true),
            (Regex, &[], Some("A|B"), "AB", false),
            (Regex, &[], Some("A|B"), "XB", false),
            // Missing / invalid pattern fails closed.
            (Regex, &[], None, "FOO", false),
            (Regex, &[], Some("("), "(", false),
        ];
        for (mode, keys, pattern, key, expected) in cases {
            assert_eq!(
                policy_allows(*mode, keys, *pattern, key),
                *expected,
                "{mode:?} {keys:?} {pattern:?} {key}"
            );
        }
    }

    #[test]
    fn compile_pattern_rejects_bad_input() {
        assert!(compile_pattern("").is_err());
        assert!(compile_pattern("(").is_err());
        assert!(compile_pattern(&"a".repeat(MAX_PATTERN_LEN + 1)).is_err());
        assert!(compile_pattern(&"a".repeat(MAX_PATTERN_LEN)).is_ok());
        // Small source, huge compiled program → rejected by size_limit.
        assert!(compile_pattern(r"\w{1000}\w{1000}").is_err());
    }

    #[test]
    fn ban_duration_escalates_and_caps() {
        assert_eq!(ban_duration_secs(100, 1), 100);
        assert_eq!(ban_duration_secs(100, 2), 200);
        assert_eq!(ban_duration_secs(100, 3), 400);
        assert_eq!(ban_duration_secs(86400, 10), MAX_BAN_SECS);
        assert_eq!(ban_duration_secs(u64::MAX, 50), MAX_BAN_SECS);
        assert_eq!(ban_duration_secs(100, 0), 100);
    }
}
