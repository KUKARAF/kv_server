use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct ScopeRule {
    pub scope: String, // scope prefix; "*" grants access to all scopes
    pub ops: String,   // comma-separated: read,write,delete,list
}

/// Returns true if `allowed` scope covers `entry_scope`.
///
/// Rules:
/// - `"*"` covers everything
/// - exact match covers itself
/// - `"osmosis"` covers `"osmosis/media"`, `"osmosis/ai"`, `"osmosis/a/b"` (any sub-scope)
pub fn scope_covers(allowed: &str, entry_scope: &str) -> bool {
    allowed == "*"
        || allowed == entry_scope
        || entry_scope.starts_with(&format!("{allowed}/"))
}

/// Returns true if any scope rule permits `op` on an entry with the given scope.
///
/// `entry_scope` is `None` for unscoped entries; only a `"*"` rule covers those.
pub fn check_scope(scopes: &[ScopeRule], entry_scope: Option<&str>, op: &str) -> bool {
    scopes.iter().any(|rule| {
        let scope_ok = match entry_scope {
            None => rule.scope == "*",
            Some(s) => scope_covers(&rule.scope, s),
        };
        scope_ok && rule.ops.split(',').any(|o| o.trim() == op)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(scope_covers("osmosis", "osmosis"));
        assert!(!scope_covers("osmosis", "osmosis2"));
        assert!(!scope_covers("osmosis", "other"));
    }

    #[test]
    fn sub_scope() {
        assert!(scope_covers("osmosis", "osmosis/media"));
        assert!(scope_covers("osmosis", "osmosis/ai"));
        assert!(scope_covers("osmosis", "osmosis/a/b/c"));
        assert!(!scope_covers("osmosis/media", "osmosis/ai"));
        assert!(!scope_covers("osmosis/media", "osmosis"));
    }

    #[test]
    fn wildcard_covers_all() {
        assert!(scope_covers("*", "osmosis"));
        assert!(scope_covers("*", "osmosis/media"));
        assert!(scope_covers("*", ""));
    }

    #[test]
    fn no_partial_prefix() {
        // "osmosis" must not cover "osmosisX" (no slash)
        assert!(!scope_covers("osmosis", "osmosisX"));
        assert!(!scope_covers("osmosis", "osmosis2/sub"));
    }

    #[test]
    fn check_scope_any_rule() {
        let scopes = vec![
            ScopeRule { scope: "osmosis".to_string(), ops: "read,list".to_string() },
            ScopeRule { scope: "other".to_string(), ops: "read".to_string() },
        ];
        assert!(check_scope(&scopes, Some("osmosis"), "read"));
        assert!(check_scope(&scopes, Some("osmosis/media"), "read"));
        assert!(check_scope(&scopes, Some("osmosis/ai"), "list"));
        assert!(!check_scope(&scopes, Some("osmosis"), "write"));
        assert!(!check_scope(&scopes, Some("unrelated"), "read"));
        assert!(!check_scope(&scopes, None, "read")); // unscoped requires "*"
    }

    #[test]
    fn unscoped_requires_wildcard() {
        let scopes = vec![
            ScopeRule { scope: "*".to_string(), ops: "read".to_string() },
        ];
        assert!(check_scope(&scopes, None, "read"));

        let scopes2 = vec![
            ScopeRule { scope: "osmosis".to_string(), ops: "read".to_string() },
        ];
        assert!(!check_scope(&scopes2, None, "read"));
    }
}
