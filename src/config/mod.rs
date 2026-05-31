pub mod action;
pub mod arg;
pub mod audit;
pub mod contract;
pub mod duration;
pub mod global;
pub mod rule;
pub mod subcommand;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::{contract::Contract, global::Global, rule::Rule};

pub type FlagGroups = HashMap<String, Vec<String>>;
pub type Contracts = HashMap<String, Contract>;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub global: Global,

    #[serde(default)]
    pub contracts: Contracts,

    #[serde(default)]
    pub flag_groups: FlagGroups,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,

    /// Allowed filesystem roots (for path validations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,

    /// Allowed systemd units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, crate::errors::GuardError> {
        let data = std::fs::read_to_string(path).map_err(|e| {
            crate::errors::GuardError::Config(format!("cannot read config file: {e}"))
        })?;
        toml::from_str(&data).map_err(|e| crate::errors::GuardError::Toml(e.to_string()))
    }

    pub fn to_toml_string(&self) -> Result<String, crate::errors::GuardError> {
        toml::to_string_pretty(self).map_err(|e| crate::errors::GuardError::Toml(e.to_string()))
    }

    pub fn write_to_file(&self, path: &str) -> Result<(), crate::errors::GuardError> {
        let toml_str = self.to_toml_string()?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::audit::AuditFormat;
    use crate::config::duration::parse_duration;
    use crate::config::duration::Duration;

    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.global.audit_format, AuditFormat::Json);
        assert_eq!(cfg.global.audit_log, "/var/log/ssh-guard-audit.log");
    }

    #[test]
    fn test_parse_subcommands() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/git", timeout = "10s" }
implicit_symlinks = false

[[rules.subcommands]]
name = "status"
args = ["--porcelain", "--short", "{string}"]

[[rules.subcommands]]
name = "log"
flags = ["--oneline"]
flag_groups = ["git-common"]

[[rules.subcommands]]
name = "remote"

[[rules.subcommands.subcommands]]
name = "add"
args = ["{gh_remote}"]

[flag_groups]
git-common = ["--no-pager"]

[global]
audit_log = "/tmp/audit.log"
help_text = "allowed: git status, git log, git remote add"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert!(!rule.implicit_symlinks);
        assert_eq!(rule.subcommands.len(), 3);

        // status subcommand
        let status = &rule.subcommands[0];
        assert_eq!(status.name, "status");
        assert_eq!(status.args, vec!["--porcelain", "--short", "{string}"]);

        // log subcommand
        let log = &rule.subcommands[1];
        assert_eq!(log.name, "log");
        assert_eq!(log.flags, vec!["--oneline"]);
        assert_eq!(log.flag_groups, vec!["git-common"]);

        // remote → add nested
        let remote = &rule.subcommands[2];
        assert_eq!(remote.name, "remote");
        assert_eq!(remote.subcommands.len(), 1);
        assert_eq!(remote.subcommands[0].name, "add");
        assert_eq!(remote.subcommands[0].args, vec!["{gh_remote}"]);

        // flag groups
        assert_eq!(cfg.flag_groups["git-common"], vec!["--no-pager"]);

        // contracts
        assert_eq!(cfg.contracts.len(), 0);

        // global
        assert_eq!(cfg.global.audit_log, "/tmp/audit.log");
        assert_eq!(
            cfg.global.help_text,
            "allowed: git status, git log, git remote add"
        );
    }

    #[test]
    fn test_duration_parsing() {
        assert_eq!(parse_duration("5000").unwrap().millis, 5000);
        assert_eq!(parse_duration("5000ms").unwrap().millis, 5000);
        assert_eq!(parse_duration("5s").unwrap().millis, 5000);
        assert_eq!(parse_duration("1m").unwrap().millis, 60000);
        assert_eq!(parse_duration("1h").unwrap().millis, 3_600_000);
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn test_duration_deser_inline() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/echo", args = [], timeout = "30s" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        match &cfg.rules[0].action {
            Action::Run { timeout, .. } => {
                assert_eq!(timeout.millis, 30_000);
            }
            _ => panic!("expected Run action"),
        }
    }

    #[test]
    fn test_duration_deser_integer() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/echo", args = [], timeout = 10000 }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        match &cfg.rules[0].action {
            Action::Run { timeout, .. } => {
                assert_eq!(timeout.millis, 10000);
            }
            _ => panic!("expected Run action"),
        }
    }

    #[test]
    fn test_parse_global_all_fields() {
        let toml_str = r#"
[global]
audit_log = "/custom/audit.log"
audit_format = "logfmt"
help_text = "Available: help"
log_tag = "my-guard"
max_read_bytes = 512000
max_tail_lines = 1000
default_tail_lines = 50

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.global.audit_log, "/custom/audit.log");
        assert_eq!(cfg.global.audit_format, AuditFormat::Logfmt);
        assert_eq!(cfg.global.help_text, "Available: help");
        assert_eq!(cfg.global.log_tag, "my-guard");
        assert_eq!(cfg.global.max_read_bytes, 512000);
        assert_eq!(cfg.global.max_tail_lines, 1000);
        assert_eq!(cfg.global.default_tail_lines, 50);
    }

    #[test]
    fn test_parse_contracts() {
        let toml_str = r#"
[contracts.port]
type = "int_range"
min = 1024
max = 65535

[contracts.svc]
type = "enum"
values = ["ssh", "nginx"]

[contracts.username]
type = "string_len"
min = 3
max = 32

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.contracts.len(), 3);
        match &cfg.contracts["port"] {
            Contract::IntRange { min, max } => {
                assert_eq!(*min, 1024);
                assert_eq!(*max, 65535);
            }
            _ => panic!("expected IntRange"),
        }
    }

    #[test]
    fn test_parse_run_action_with_timeout() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/usr/bin/rsync", args = ["-a", "{string}"], timeout = "2m" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        match &cfg.rules[0].action {
            Action::Run {
                binary,
                args,
                timeout,
            } => {
                assert_eq!(binary, "/usr/bin/rsync");
                assert_eq!(args, &vec!["-a", "{string}"]);
                assert_eq!(timeout.millis, 120_000);
            }
            _ => panic!("expected Run action"),
        }
    }

    #[test]
    fn test_parse_all_action_types() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/echo", args = ["hello"] }

[[rules]]
action = { type = "read_file", path_capture = "{log}", root_set = "logs" }

[[rules]]
action = { type = "tail_file", path_capture = "{log}", default_lines = 50, root_set = "logs" }

[[rules]]
action = { type = "stat_path", path_capture = "{path}", root_set = "files" }

[[rules]]
action = { type = "list_dir", path_capture = "{dir}", root_set = "files" }

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 6);

        // TailFile has explicit default_lines
        match &cfg.rules[2].action {
            Action::TailFile { default_lines, .. } => {
                assert_eq!(*default_lines, 50);
            }
            _ => panic!("expected TailFile at index 2"),
        }
    }

    #[test]
    fn test_parse_flag_groups_in_config() {
        let toml_str = r#"
[flag_groups]
net = ["--host", "-p"]
fmt = ["--format", "-f"]

[[rules]]
action = { type = "run", binary = "/usr/bin/curl" }
flags = ["--verbose"]
flag_groups = ["net"]

[[rules.subcommands]]
name = "get"
flag_groups = ["fmt"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        // flag groups at top level
        assert_eq!(cfg.flag_groups["net"], vec!["--host", "-p"]);
        assert_eq!(cfg.flag_groups["fmt"], vec!["--format", "-f"]);

        // rule references flag_groups
        let rule = &cfg.rules[0];
        assert_eq!(rule.flag_groups, vec!["net"]);
        assert_eq!(rule.flags, vec!["--verbose"]);

        // subcommand references flag_groups
        assert_eq!(rule.subcommands[0].flag_groups, vec!["fmt"]);
    }

    #[test]
    fn test_parse_implicit_symlinks() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/usr/bin/realcmd" }
implicit_symlinks = false

[[rules]]
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
# implicit_symlinks not set → default true
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 2);

        assert!(!cfg.rules[0].implicit_symlinks);
        assert!(cfg.rules[1].implicit_symlinks);
    }

    #[test]
    fn test_parse_template_suffix_in_config() {
        let toml_str = r#"
[contracts.unit]
type = "enum"
values = ["nginx", "sshd"]

[[rules]]
action = { type = "run", binary = "/usr/bin/systemctl" }

[[rules.subcommands]]
name = "status"
args = ["{unit}.service"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        // contract present
        assert!(cfg.contracts.contains_key("unit"));

        // arg stored as-is with ".service" suffix
        let rule = &cfg.rules[0];
        assert_eq!(rule.subcommands[0].args, vec!["{unit}.service"]);
    }

    #[test]
    fn test_parse_subcommand_arg_style_override() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/usr/bin/some-tool" }
arg_style = "gnu_long"

[[rules.subcommands]]
name = "legacy"
arg_style = "dos"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let rule = &cfg.rules[0];
        assert_eq!(rule.arg_style, ArgStyle::GnuLong);
        assert_eq!(rule.subcommands[0].arg_style, Some(ArgStyle::Dos));
    }

    #[test]
    fn test_config_round_trip() {
        use crate::config::contract::Contract;

        let original = Config {
            global: Global {
                audit_log: "/tmp/roundtrip.log".into(),
                audit_format: AuditFormat::Logfmt,
                help_text: "round trip test".into(),
                log_tag: "test".into(),
                max_read_bytes: 999,
                max_tail_lines: 111,
                default_tail_lines: 50,
            },
            contracts: {
                let mut c = Contracts::new();
                c.insert("port".into(), Contract::IntRange { min: 1, max: 9999 });
                c
            },
            flag_groups: {
                let mut f = FlagGroups::new();
                f.insert(
                    "verbose".into(),
                    vec!["-v".to_string(), "--verbose".to_string()],
                );
                f
            },
            rules: vec![Rule {
                action: Action::Run {
                    binary: "/bin/test".into(),
                    args: vec!["{arg}".into()],
                    timeout: Duration { millis: 10000 },
                },
                command: Some("test".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["verbose".into()],
                flags: vec!["--debug".into()],
                args: vec!["{string}".into()],
                pre_args: vec!["--config".to_string(), "/etc/test.conf".to_string()],
                subcommands: vec![],
            }],
            roots: vec!["/data".into()],
            units: vec!["nginx".into(), "sshd".into()],
        };

        let toml_str = original.to_toml_string().unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        // Compare key fields
        assert_eq!(deserialized.global.audit_log, "/tmp/roundtrip.log");
        assert_eq!(deserialized.global.audit_format, AuditFormat::Logfmt);
        assert_eq!(deserialized.global.help_text, "round trip test");
        assert_eq!(deserialized.global.max_read_bytes, 999);

        assert!(deserialized.contracts.contains_key("port"));
        assert_eq!(deserialized.flag_groups["verbose"], vec!["-v", "--verbose"]);

        assert_eq!(deserialized.rules.len(), 1);
        let r = &deserialized.rules[0];
        assert_eq!(r.command, Some("test".into()));
        match &r.action {
            Action::Run {
                binary,
                args,
                timeout,
            } => {
                assert_eq!(binary, "/bin/test");
                assert_eq!(args, &vec!["{arg}".to_string()]);
                assert_eq!(timeout.millis, 10000);
            }
            _ => panic!("expected Run"),
        }
        assert_eq!(r.flag_groups, vec!["verbose"]);
        assert_eq!(r.flags, vec!["--debug"]);
        assert_eq!(r.args, vec!["{string}"]);
        assert_eq!(r.pre_args, vec!["--config", "/etc/test.conf"]);

        assert_eq!(deserialized.roots, vec!["/data"]);
        assert_eq!(deserialized.units, vec!["nginx", "sshd"]);
    }

    #[test]
    fn test_parse_roots_and_units() {
        let toml_str = r#"
roots = ["/var/log", "/home"]
units = ["nginx", "postgresql", "sshd"]

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.roots, vec!["/var/log", "/home"]);
        assert_eq!(cfg.units, vec!["nginx", "postgresql", "sshd"]);
    }

    #[test]
    fn test_from_file_nonexistent() {
        let path = "/tmp/__ssh_guard_test_nonexistent_should_not_exist.toml";
        let result = Config::from_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_to_file_round_trip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let cfg = Config {
            global: Global {
                audit_log: "/tmp/write_test.log".into(),
                audit_format: AuditFormat::Json,
                help_text: "write test".into(),
                log_tag: "test".into(),
                max_read_bytes: 1024,
                max_tail_lines: 100,
                default_tail_lines: 20,
            },
            contracts: Contracts::new(),
            flag_groups: FlagGroups::new(),
            rules: vec![Rule {
                action: Action::Run {
                    binary: "/bin/ls".into(),
                    args: vec!["-la".into()],
                    timeout: Duration { millis: 5000 },
                },
                command: None,
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            }],
            roots: vec![],
            units: vec![],
        };

        // Write, then read back
        cfg.write_to_file(&path).unwrap();
        let read_back = Config::from_file(&path).unwrap();

        assert_eq!(read_back.global.audit_log, "/tmp/write_test.log");
        assert_eq!(read_back.global.help_text, "write test");
        assert_eq!(read_back.rules.len(), 1);
        match &read_back.rules[0].action {
            Action::Run { binary, .. } => assert_eq!(binary, "/bin/ls"),
            _ => panic!("expected Run"),
        }

        // Cleanup
        drop(tmp);
    }

    #[test]
    fn test_config_empty_rules() {
        // rules has #[serde(default)] — no [[rules]] entries is ok, becomes empty vec
        let toml_str = r#"
[global]
audit_log = "/dev/null"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(
            result.is_ok(),
            "empty rules should parse with #[serde(default)]"
        );
        let cfg = result.unwrap();
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn test_parse_rule_with_flags_and_pre_args() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/usr/bin/deploy", args = ["--env", "{string}"] }
flags = ["--dry-run", "--verbose"]
pre_args = ["--config", "/etc/deploy.conf"]
args = ["{string}"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert_eq!(rule.flags, vec!["--dry-run", "--verbose"]);
        assert_eq!(rule.pre_args, vec!["--config", "/etc/deploy.conf"]);
        assert_eq!(rule.args, vec!["{string}"]);
        // No subcommands
        assert!(rule.subcommands.is_empty());
    }
}
