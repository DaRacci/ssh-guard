use serde::{Deserialize, Serialize};

use crate::config::audit::AuditFormat;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Global {
    /// Path to audit log file. All actions (success + failure) are appended.
    #[serde(default = "default_audit_log")]
    pub audit_log: String,

    /// Audit output format: "json" or "logfmt".
    #[serde(default)]
    pub audit_format: AuditFormat,

    /// Help text shown when SSH_ORIGINAL_COMMAND is empty.
    #[serde(default)]
    pub help_text: String,

    /// Syslog tag for non-audit logging.
    #[serde(default = "default_log_tag")]
    pub log_tag: String,

    /// Maximum bytes for read_file action.
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: usize,

    /// Maximum lines for tail_file action.
    #[serde(default = "default_max_tail_lines")]
    pub max_tail_lines: usize,

    /// Default lines for tail_file when not specified.
    #[serde(default = "default_tail_lines_global")]
    pub default_tail_lines: usize,
}

fn default_audit_log() -> String {
    "/var/log/ssh-guard-audit.log".into()
}

fn default_log_tag() -> String {
    "ssh-guard".into()
}

const fn default_max_read_bytes() -> usize {
    1024 * 1024
}

const fn default_max_tail_lines() -> usize {
    5000
}

const fn default_tail_lines_global() -> usize {
    200
}

impl Default for Global {
    fn default() -> Self {
        Self {
            audit_log: default_audit_log(),
            audit_format: AuditFormat::default(),
            help_text: String::new(),
            log_tag: default_log_tag(),
            max_read_bytes: default_max_read_bytes(),
            max_tail_lines: default_max_tail_lines(),
            default_tail_lines: default_tail_lines_global(),
        }
    }
}
