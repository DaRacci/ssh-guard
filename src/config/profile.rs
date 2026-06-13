use serde::{Deserialize, Serialize};

use crate::config::{Contracts, FlagGroups, audit::AuditFormat, global::Global, rule::Rule};

/// Field-wise overrides for `Global` settings within a profile.
/// Each field is `Option` so only explicitly-set fields override the base.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_format: Option<AuditFormat>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_text: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_tag: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_read_bytes: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tail_lines: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_tail_lines: Option<usize>,
}

impl GlobalOverride {
    /// Merge these overrides into a base `Global`, returning the result.
    pub fn apply_to(&self, base: &Global) -> Global {
        Global {
            audit_log: self
                .audit_log
                .clone()
                .unwrap_or_else(|| base.audit_log.clone()),
            audit_format: self
                .audit_format
                .clone()
                .unwrap_or(base.audit_format.clone()),
            help_text: self
                .help_text
                .clone()
                .unwrap_or_else(|| base.help_text.clone()),
            log_tag: self.log_tag.clone().unwrap_or_else(|| base.log_tag.clone()),
            max_read_bytes: self.max_read_bytes.unwrap_or(base.max_read_bytes),
            max_tail_lines: self.max_tail_lines.unwrap_or(base.max_tail_lines),
            default_tail_lines: self.default_tail_lines.unwrap_or(base.default_tail_lines),
        }
    }
}

/// A named profile that extends base config for specific SSH users.
///
/// TOML shape:
/// ```toml
/// [profiles.admin]
/// users = ["alice", "bob"]
/// [profiles.admin.global]
/// audit_log = "/var/log/admin-audit.log"
/// [[profiles.admin.rules]]
/// action = { type = "show_help" }
/// ```
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct Profile {
    /// SSH usernames this profile applies to.
    pub users: Vec<String>,

    /// Optional field-wise overrides for `[global]` settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalOverride>,

    /// Optional contract overrides (map merge, profile keys win).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contracts: Option<Contracts>,

    /// Optional flag-group overrides (map merge, profile keys win).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag_groups: Option<FlagGroups>,

    /// Optional additional rules (appended after base rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<Rule>>,

    /// Optional additional roots (appended unique, base-first order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<Vec<String>>,

    /// Optional additional units (appended unique, base-first order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub units: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::global::Global;

    #[test]
    fn test_global_override_apply_all() {
        let base = Global::default();
        let ov = GlobalOverride {
            audit_log: Some("/custom/log".into()),
            audit_format: Some(AuditFormat::Logfmt),
            help_text: Some("custom help".into()),
            log_tag: Some("custom-tag".into()),
            max_read_bytes: Some(999),
            max_tail_lines: Some(100),
            default_tail_lines: Some(10),
        };
        let merged = ov.apply_to(&base);
        assert_eq!(merged.audit_log, "/custom/log");
        assert_eq!(merged.audit_format, AuditFormat::Logfmt);
        assert_eq!(merged.help_text, "custom help");
        assert_eq!(merged.log_tag, "custom-tag");
        assert_eq!(merged.max_read_bytes, 999);
        assert_eq!(merged.max_tail_lines, 100);
        assert_eq!(merged.default_tail_lines, 10);
    }

    #[test]
    fn test_global_override_apply_partial() {
        let base = Global::default();
        let ov = GlobalOverride {
            audit_log: Some("/custom/log".into()),
            ..Default::default()
        };
        let merged = ov.apply_to(&base);
        assert_eq!(merged.audit_log, "/custom/log");
        assert_eq!(merged.audit_format, base.audit_format);
        assert_eq!(merged.log_tag, base.log_tag);
    }

    #[test]
    fn test_global_override_apply_none() {
        let base = Global::default();
        let ov = GlobalOverride::default();
        let merged = ov.apply_to(&base);
        assert_eq!(merged.audit_log, base.audit_log);
        assert_eq!(merged.audit_format, base.audit_format);
    }

    #[test]
    fn test_profile_deserialize() {
        let toml_str = r#"
users = ["alice", "bob"]
[global]
audit_log = "/custom/log"
"#;
        let profile: Profile = toml::from_str(toml_str).unwrap();
        assert_eq!(profile.users, vec!["alice", "bob"]);
        assert_eq!(
            profile.global.as_ref().unwrap().audit_log.as_deref(),
            Some("/custom/log")
        );
        assert!(profile.contracts.is_none());
        assert!(profile.flag_groups.is_none());
        assert!(profile.rules.is_none());
    }

    #[test]
    fn test_profile_minimal() {
        let toml_str = r#"users = ["charlie"]"#;
        let profile: Profile = toml::from_str(toml_str).unwrap();
        assert_eq!(profile.users, vec!["charlie"]);
        assert!(profile.global.is_none());
    }
}
