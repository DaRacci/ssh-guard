use thiserror::Error;

pub type Result<T> = std::result::Result<T, GuardError>;

/// One specific failure when trying to match a command against a rule tree.
#[derive(Debug, Clone)]
pub struct MatchFailure {
    /// Index into Config.rules
    pub rule_index: usize,

    /// Subcommand path we had traversed when the failure occurred.
    /// e.g. ["git", "remote"] means we got past "git" then "remote" but failed deeper.
    pub subcommand_path: Vec<String>,

    /// 0-based token index in the original command argv that caused the failure.
    pub at_token: usize,

    /// The token value at that position.
    pub token: String,

    /// Human-readable reason.
    pub reason: String,
}

impl std::fmt::Display for MatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = if self.subcommand_path.is_empty() {
            String::new()
        } else {
            format!(" (via {})", self.subcommand_path.join(" "))
        };
        write!(
            f,
            "rule[{}]{}: token {} '{}' — {}",
            self.rule_index, path, self.at_token, self.token, self.reason
        )
    }
}

#[derive(Error, Debug)]
pub enum GuardError {
    #[error("config error: {0}")]
    Config(String),

    #[error("no SSH_ORIGINAL_COMMAND set")]
    NoCommand,

    #[error("invalid command: {0}")]
    ParseCommand(String),

    /// No rule matched. `failures` contains every attempted match and why it failed.
    #[error("no matching rule")]
    NoMatch {
        command: String,
        failures: Vec<MatchFailure>,
    },

    #[error("constraint violation: {0}")]
    Constraint(String),

    #[error("path not allowed: {0}")]
    PathNotAllowed(String),

    #[error("action failed: {0}")]
    Action(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML error: {0}")]
    Toml(String),
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;

    // ── MatchFailure Display ──────────────────────────────────────────

    #[test]
    fn match_failure_display_empty_path() {
        let f = MatchFailure {
            rule_index: 3,
            subcommand_path: vec![],
            at_token: 1,
            token: "foo".into(),
            reason: "unexpected token".into(),
        };
        let got = f.to_string();
        assert_eq!(got, "rule[3]: token 1 'foo' — unexpected token");
    }

    #[test]
    fn match_failure_display_with_path() {
        let f = MatchFailure {
            rule_index: 0,
            subcommand_path: vec!["git".into(), "remote".into()],
            at_token: 2,
            token: "add".into(),
            reason: "not a valid subcommand".into(),
        };
        let got = f.to_string();
        assert_eq!(
            got,
            "rule[0] (via git remote): token 2 'add' — not a valid subcommand"
        );
    }

    #[test]
    fn match_failure_display_single_subcommand() {
        let f = MatchFailure {
            rule_index: 1,
            subcommand_path: vec!["status".into()],
            at_token: 0,
            token: "status".into(),
            reason: "wrong flags".into(),
        };
        let got = f.to_string();
        assert_eq!(got, "rule[1] (via status): token 0 'status' — wrong flags");
    }

    // ── GuardError Display ────────────────────────────────────────────

    #[test]
    fn guard_error_config() {
        let e = GuardError::Config("bad thing".into());
        assert_eq!(e.to_string(), "config error: bad thing");
    }

    #[test]
    fn guard_error_no_command() {
        let e = GuardError::NoCommand;
        assert_eq!(e.to_string(), "no SSH_ORIGINAL_COMMAND set");
    }

    #[test]
    fn guard_error_parse_command() {
        let e = GuardError::ParseCommand("bad cmd".into());
        assert_eq!(e.to_string(), "invalid command: bad cmd");
    }

    #[test]
    fn guard_error_no_match() {
        let failures = vec![MatchFailure {
            rule_index: 0,
            subcommand_path: vec![],
            at_token: 0,
            token: "xyz".into(),
            reason: "no matching rule".into(),
        }];
        let e = GuardError::NoMatch {
            command: "xyz".into(),
            failures,
        };
        assert_eq!(e.to_string(), "no matching rule");
    }

    #[test]
    fn guard_error_constraint() {
        let e = GuardError::Constraint("out of range".into());
        assert_eq!(e.to_string(), "constraint violation: out of range");
    }

    #[test]
    fn guard_error_path_not_allowed() {
        let e = GuardError::PathNotAllowed("/etc/passwd".into());
        assert_eq!(e.to_string(), "path not allowed: /etc/passwd");
    }

    #[test]
    fn guard_error_action() {
        let e = GuardError::Action("timeout".into());
        assert_eq!(e.to_string(), "action failed: timeout");
    }

    #[test]
    fn guard_error_validation() {
        let e = GuardError::Validation("bad type".into());
        assert_eq!(e.to_string(), "validation error: bad type");
    }

    #[test]
    fn guard_error_io() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "disk full");
        let e = GuardError::Io(inner);
        assert_eq!(e.to_string(), "IO error: disk full");
    }

    #[test]
    fn guard_error_toml() {
        let e = GuardError::Toml("syntax error".into());
        assert_eq!(e.to_string(), "TOML error: syntax error");
    }

    // ── Debug output ──────────────────────────────────────────────────

    #[test]
    fn match_failure_debug() {
        let f = MatchFailure {
            rule_index: 2,
            subcommand_path: vec!["a".into(), "b".into()],
            at_token: 1,
            token: "x".into(),
            reason: "y".into(),
        };
        let debug = format!("{f:?}");
        assert!(debug.contains("rule_index: 2"));
        assert!(debug.contains("\"a\""));
        assert!(debug.contains("\"b\""));
        assert!(debug.contains("at_token: 1"));
        assert!(debug.contains("\"x\""));
        assert!(debug.contains("\"y\""));
    }

    #[test]
    fn guard_error_debug() {
        let e = GuardError::Config("test".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("Config"));
        assert!(debug.contains("test"));

        let e2 = GuardError::NoCommand;
        let debug2 = format!("{e2:?}");
        assert!(debug2.contains("NoCommand"));

        let e3 = GuardError::Io(std::io::Error::new(std::io::ErrorKind::Other, "err"));
        let debug3 = format!("{e3:?}");
        assert!(debug3.contains("Io"));
    }
}
