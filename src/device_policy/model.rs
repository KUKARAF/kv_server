use serde::{Deserialize, Serialize};

/// Max length of a regex policy pattern (before anchoring).
pub const MAX_PATTERN_LEN: usize = 512;
/// Max length of a single KV entry name in an allow/deny list.
pub const MAX_KEY_LEN: usize = 256;
/// Max number of entries in an allow/deny list.
pub const MAX_KEYS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    AllowAll,
    AllowList,
    DenyList,
    Regex,
}

impl PolicyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow_all" => Some(Self::AllowAll),
            "allow_list" => Some(Self::AllowList),
            "deny_list" => Some(Self::DenyList),
            "regex" => Some(Self::Regex),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowAll => "allow_all",
            Self::AllowList => "allow_list",
            Self::DenyList => "deny_list",
            Self::Regex => "regex",
        }
    }
}

/// Ban state of a device. `active` is false for a lifted/expired ban whose history
/// (`ban_count`, `last_key`) is retained for escalation.
#[derive(Debug, Clone, Serialize)]
pub struct BanInfo {
    pub banned_at: Option<String>,
    pub unban_at: Option<String>,
    pub ban_count: i64,
    pub last_key: Option<String>,
    pub active: bool,
}

/// One row of `GET /api/admin/device-policies` (also the `PUT` response).
#[derive(Debug, Clone, Serialize)]
pub struct DevicePolicyRow {
    pub device_id: String,
    pub device_name: String,
    pub mode: String,
    pub keys: Vec<String>,
    pub pattern: Option<String>,
    pub ban: Option<BanInfo>,
}

/// One row of `GET /api/admin/device-policies/bans`: the ban object plus device id/name.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveBanRow {
    pub device_id: String,
    pub device_name: String,
    #[serde(flatten)]
    pub ban: BanInfo,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub mode: String,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub pattern: Option<String>,
}
