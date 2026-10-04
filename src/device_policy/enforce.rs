//! Enforcement of per-device key policies and device bans.
//!
//! Every device-attributable request runs `ensure_not_banned`; every device-attributable
//! read, write, delete or import of a specific KV entry runs `authorize_key` (ban check +
//! policy check, and on violation: escalating ban + notification). Listings are filtered by
//! `listing_filter` (never a violation). Identity/credential management from a restricted
//! device is refused by `ensure_may_manage_credentials` (plain 403, no ban).
//!
//! "Device-attributable" = authenticated by an `api_keys` row whose `device_id` is set: the
//! device-bound session minted by session-request approval, AND every credential a device
//! session itself minted (API keys, session keys, CLI/approval tokens), which inherit the
//! minting device's id so its ban and policy follow them. Both reject with `AppError::DeviceBanned`,
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
use std::{collections::HashSet, net::IpAddr};

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
    // The BARE pattern must compile on its own first. Otherwise unbalanced parentheses can
    // close the wrapping group and escape the anchors: `FOO)|(.*` is invalid alone but
    // `^(?:FOO)|(.*)$` compiles and matches every name.
    build_limited(pattern)?;
    build_limited(&format!("^(?:{pattern})$"))
}

fn build_limited(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
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

/// The one guard for identity / credential management from a device-bound session.
///
/// A policy-restricted device must not mint fresh credentials (API keys, CLI/approval
/// tokens, session keys), obtain management-key material, register or delete passkeys,
/// enrol or link devices, or approve a session request for a device other than itself:
/// each of those would let it build an unrestricted "twin" and sidestep its own policy.
/// Plain 403 (`Forbidden`, no ban, no AuthFailed marker) — it is not a KV read.
/// Unrestricted (allow_all / no policy) devices and non-device sessions pass; a banned
/// device never gets here (AdminAuth already rejected it).
pub async fn ensure_may_manage_credentials(
    pool: &SqlitePool,
    claims: &SessionClaims,
) -> Result<(), AppError> {
    if let Some(device_id) = claims.device_id.as_deref() {
        if is_restricted(pool, device_id).await? {
            return Err(forbidden_for_device());
        }
    }
    Ok(())
}

/// The `Forbidden` returned by [`ensure_may_manage_credentials`].
pub fn forbidden_for_device() -> AppError {
    AppError::Forbidden("not permitted for this device".to_string())
}

/// Name filter for listings (KV key names only, never values). Listing never bans: a
/// restricted device simply doesn't see names its policy would refuse.
pub enum KeyFilter {
    /// Non-device caller or allow_all device: everything is visible.
    All,
    Policy {
        mode: PolicyMode,
        keys: HashSet<String>,
        /// Compiled once per listing; `None` for a regex policy fails closed.
        re: Option<Regex>,
    },
}

impl KeyFilter {
    pub fn allows(&self, kv_key: &str) -> bool {
        match self {
            KeyFilter::All => true,
            KeyFilter::Policy { mode, keys, re } => match mode {
                PolicyMode::AllowAll => true,
                PolicyMode::AllowList => keys.contains(kv_key),
                PolicyMode::DenyList => !keys.contains(kv_key),
                PolicyMode::Regex => re.as_ref().is_some_and(|r| r.is_match(kv_key)),
            },
        }
    }
}

/// Builds the listing filter for the (optional) device behind a request.
pub async fn listing_filter(
    pool: &SqlitePool,
    device_id: Option<&str>,
) -> Result<KeyFilter, AppError> {
    let Some(device_id) = device_id else {
        return Ok(KeyFilter::All);
    };
    Ok(match load_policy(pool, device_id).await? {
        None => KeyFilter::All,
        Some(p) if p.mode == PolicyMode::AllowAll => KeyFilter::All,
        Some(p) => KeyFilter::Policy {
            mode: p.mode,
            re: p
                .pattern
                .as_deref()
                .and_then(|pat| compile_pattern(pat).ok()),
            keys: p.keys.into_iter().collect(),
        },
    })
}

/// Ban check, then policy check for a device-attributable read, write or delete of
/// `kv_key`. Only ever called with the AUTHENTICATED device id (never a path parameter),
/// so nobody can get someone else's device banned. On violation
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
            // Unbalanced parens must not escape the anchors (they don't compile bare).
            (Regex, &[], Some("FOO)|(.*"), "SECRET_DB", false),
            (Regex, &[], Some("FOO)|(.*"), "FOO", false),
            (Regex, &[], Some("FOO)|.*(?:"), "SECRET_DB", false),
            (Regex, &[], Some("a)|(b"), "a", false),
            (Regex, &[], Some("a)|(b"), "b", false),
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
        for escape in ["FOO)|(.*", "FOO)|.*(?:", "a)|(b"] {
            assert!(compile_pattern(escape).is_err(), "{escape}");
        }
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
