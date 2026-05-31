use serde::{Deserialize, Serialize};

use crate::config::arg::ArgStyle;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Subcommand {
    pub name: String,

    /// Override arg_style for this subcommand level (inherits parent if None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_style: Option<ArgStyle>,

    /// Flag-group names to resolve from Config.flag_groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_groups: Vec<String>,

    /// Inline allowed flags / switches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,

    /// Allowed arguments (set, not ordered). May contain:
    ///   - literal strings: "--porcelain", "-n"
    ///   - templates:         "{string}", "{int}", "{any}", "{port}", "{int|string}"
    ///   - inline templates:  "--depth={int}"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Static args injected after this subcommand name at execution time.
    /// No template substitution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_args: Vec<String>,

    /// Nested subcommands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subcommands: Vec<Subcommand>,
}
