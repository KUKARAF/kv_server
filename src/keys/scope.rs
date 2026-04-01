use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScopeRule {
    pub key_pattern: String,
    pub ops: String,
}

/// Check if `key` matches `pattern` where `*` is a wildcard.
/// Supports a single `*` anywhere in the pattern.
pub fn matches_pattern(pattern: &str, key: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == key,
        Some((prefix, suffix)) => {
            key.starts_with(prefix)
                && key.ends_with(suffix)
                && key.len() >= prefix.len() + suffix.len()
        }
    }
}

/// Returns true if any scope rule permits `op` on `key`.
pub fn check_scope(scopes: &[ScopeRule], key: &str, op: &str) -> bool {
    scopes.iter().any(|rule| {
        matches_pattern(&rule.key_pattern, key)
            && rule.ops.split(',').any(|o| o.trim() == op)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(matches_pattern("app-version", "app-version"));
        assert!(!matches_pattern("app-version", "app-version2"));
    }

    #[test]
    fn suffix_wildcard() {
        assert!(matches_pattern("payments-*", "payments-prod"));
        assert!(matches_pattern("payments-*", "payments-"));
        assert!(!matches_pattern("payments-*", "other-prod"));
    }

    #[test]
    fn prefix_wildcard() {
        assert!(matches_pattern("*-prod", "payments-prod"));
        assert!(!matches_pattern("*-prod", "payments-staging"));
    }

    #[test]
    fn both_wildcard() {
        assert!(matches_pattern("app-*-v2", "app-payments-v2"));
        assert!(!matches_pattern("app-*-v2", "app-payments-v3"));
    }

    #[test]
    fn star_matches_all() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("*", ""));
    }

    #[test]
    fn scope_check() {
        let scopes = vec![
            ScopeRule { key_pattern: "payments-*".to_string(), ops: "read,write".to_string() },
            ScopeRule { key_pattern: "app-version".to_string(), ops: "read".to_string() },
        ];
        assert!(check_scope(&scopes, "payments-prod", "read"));
        assert!(check_scope(&scopes, "payments-prod", "write"));
        assert!(!check_scope(&scopes, "payments-prod", "delete"));
        assert!(check_scope(&scopes, "app-version", "read"));
        assert!(!check_scope(&scopes, "app-version", "write"));
        assert!(!check_scope(&scopes, "other-key", "read"));
    }
}
