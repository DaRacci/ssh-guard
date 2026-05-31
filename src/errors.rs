use thiserror::Error;

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
