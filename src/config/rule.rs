use serde::{Deserialize, Serialize};

use crate::config::{action::Action, arg::ArgStyle, subcommand::Subcommand};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub action: Action,

    /// The first token users must type to match this rule.
    /// For `Run` actions this defaults to the binary filename if unset.
    /// Required for non-Run actions (read_file, show_help, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// If false, the binary path MUST resolve to a real file (not a symlink).
    /// If true, symlinks are followed and the resolved target is used.
    #[serde(default = "default_implicit")]
    pub implicit_symlinks: bool,

    /// Default arg style for this rule + all subcommands (unless overridden).
    #[serde(default)]
    pub arg_style: ArgStyle,

    /// Flag groups applied at the top-level (before any subcommand).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flag_groups: Vec<String>,

    /// Inline flags allowed at the top level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,

    /// Allowed arguments when there are no subcommands.
    /// Same syntax as subcommand args (literals, templates, inline flags).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Static args prepended before user argv. No template substitution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_args: Vec<String>,

    /// Subcommands form the command tree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subcommands: Vec<Subcommand>,
}

impl Rule {
    /// Resolve the command name for this rule.
    /// Returns the explicit `command` field, or derives from binary filename for Run actions.
    pub fn command_name(&self) -> Option<&str> {
        if let Some(ref cmd) = self.command {
            return Some(cmd.as_str());
        }
        match &self.action {
            Action::Run { binary, .. } => std::path::Path::new(binary)
                .file_name()
                .and_then(|f| f.to_str()),
            _ => None,
        }
    }
}

#[coverage(off)]
const fn default_implicit() -> bool {
    true
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;

    #[test]
    fn test_command_name_from_explicit() {
        let rule = Rule {
            action: Action::Run {
                binary: "/usr/bin/git".into(),
                args: vec![],
                timeout: Default::default(),
            },
            command: Some("git".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        assert_eq!(rule.command_name(), Some("git"));
    }

    #[test]
    fn test_command_name_from_binary() {
        let rule = Rule {
            action: Action::Run {
                binary: "/usr/bin/systemctl".into(),
                args: vec![],
                timeout: Default::default(),
            },
            command: None,
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        assert_eq!(rule.command_name(), Some("systemctl"));
    }

    #[test]
    fn test_command_name_non_run_no_command() {
        let rule = Rule {
            action: Action::ShowHelp,
            command: None,
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        assert_eq!(rule.command_name(), None);
    }

    #[test]
    fn test_command_name_non_run_with_command() {
        let rule = Rule {
            action: Action::ShowHelp,
            command: Some("help".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        assert_eq!(rule.command_name(), Some("help"));
    }

    #[test]
    fn test_command_name_binary_no_filename() {
        // binary = "/" has no filename component
        let rule = Rule {
            action: Action::Run {
                binary: "/".into(),
                args: vec![],
                timeout: Default::default(),
            },
            command: None,
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        assert_eq!(rule.command_name(), None);
    }

    #[test]
    fn test_implicit_symlinks_default() {
        let toml_str = r#"
action = { type = "run", binary = "/bin/true" }
"#;
        let rule: Rule = toml::from_str(toml_str).unwrap();
        assert!(rule.implicit_symlinks);
    }

    #[test]
    fn test_arg_style_default() {
        let toml_str = r#"
action = { type = "run", binary = "/bin/true" }
"#;
        let rule: Rule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.arg_style, ArgStyle::GnuLong);
    }

    #[test]
    fn test_flags_and_flag_groups_default_empty() {
        let toml_str = r#"
action = { type = "run", binary = "/bin/true" }
"#;
        let rule: Rule = toml::from_str(toml_str).unwrap();
        assert!(rule.flags.is_empty());
        assert!(rule.flag_groups.is_empty());
        assert!(rule.args.is_empty());
        assert!(rule.pre_args.is_empty());
        assert!(rule.subcommands.is_empty());
    }
}
