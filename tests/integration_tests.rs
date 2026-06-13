use ssh_guard::config::{
    self, action::Action, arg::ArgStyle, audit::AuditFormat, contract::Contract, rule::Rule,
    subcommand::Subcommand,
};
use std::collections::HashMap;

#[test]
fn test_full_config_round_trip_via_file() {
    // Create config programmatically, write to file, read back, verify
    let cfg = config::Config {
        global: config::global::Global {
            audit_log: "/tmp/test-audit.log".into(),
            audit_format: AuditFormat::Logfmt,
            help_text: "test help".into(),
            log_tag: "test-tag".into(),
            ..Default::default()
        },
        contracts: {
            let mut c = HashMap::new();
            c.insert(
                "svc".into(),
                Contract::Enum {
                    values: vec!["ssh".into(), "nginx".into()],
                },
            );
            c
        },
        flag_groups: {
            let mut f = HashMap::new();
            f.insert("common".into(), vec!["--no-pager".into(), "--full".into()]);
            f
        },
        rules: vec![
            Rule {
                action: Action::Run {
                    binary: "/usr/bin/systemctl".into(),
                    args: vec!["--system".into()],
                    timeout: config::duration::Duration { millis: 10000 },
                },
                command: Some("systemctl".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["common".into()],
                flags: vec!["--no-legend".into()],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![Subcommand {
                    name: "status".into(),
                    arg_style: Some(ArgStyle::Dos),
                    flag_groups: vec![],
                    flags: vec!["/verbose".into()],
                    args: vec!["{string}.service".into()],
                    pre_args: vec!["--no-pager".into()],
                    subcommands: vec![],
                }],
            },
            Rule {
                action: Action::ShowHelp,
                command: Some("help".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            },
        ],
        roots: vec!["/var/log".into()],
        units: vec!["sshd.service".into()],
        ..Default::default()
    };

    // Write to temp file
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("roundtrip.toml");
    let path_str = config_path.to_str().unwrap();

    cfg.write_to_file(path_str).unwrap();

    // Read back
    let loaded = config::Config::from_file(path_str).unwrap();

    assert_eq!(loaded.rules.len(), 2);
    assert_eq!(loaded.global.audit_log, "/tmp/test-audit.log");
    assert_eq!(loaded.global.audit_format, AuditFormat::Logfmt);
    assert_eq!(loaded.global.help_text, "test help");
    assert_eq!(loaded.flag_groups.len(), 1);
    assert_eq!(loaded.flag_groups["common"].len(), 2);
    assert_eq!(loaded.roots, vec!["/var/log"]);
    assert!(loaded.contracts.contains_key("svc"));

    // Verify rule 0
    let r0 = &loaded.rules[0];
    assert_eq!(r0.command_name(), Some("systemctl"));
    assert_eq!(r0.flag_groups, vec!["common"]);
    assert_eq!(r0.flags, vec!["--no-legend"]);
    assert_eq!(r0.subcommands.len(), 1);
    assert_eq!(r0.subcommands[0].name, "status");
    assert_eq!(r0.subcommands[0].arg_style, Some(ArgStyle::Dos));
    assert_eq!(r0.subcommands[0].pre_args, vec!["--no-pager"]);
    assert_eq!(r0.subcommands[0].args, vec!["{string}.service"]);

    // Verify rule 1
    let r1 = &loaded.rules[1];
    assert_eq!(r1.command_name(), Some("help"));
    assert!(matches!(r1.action, Action::ShowHelp));
}

#[test]
fn test_full_config_round_trip_via_toml_string() {
    // Programmatic -> TOML string -> parse -> verify
    let cfg = config::Config {
        rules: vec![Rule {
            action: Action::Run {
                binary: "/bin/echo".into(),
                args: vec!["-n".into()],
                timeout: config::duration::Duration { millis: 3000 },
            },
            command: None,
            implicit_symlinks: false,
            arg_style: ArgStyle::PosixShort,
            flag_groups: vec![],
            flags: vec!["-e".into()],
            args: vec!["{string}".into()],
            pre_args: vec![],
            subcommands: vec![],
        }],
        ..Default::default()
    };

    let toml_str = cfg.to_toml_string().unwrap();
    let loaded: config::Config = toml::from_str(&toml_str).unwrap();

    assert_eq!(loaded.rules.len(), 1);
    let r = &loaded.rules[0];
    assert_eq!(r.arg_style, ArgStyle::PosixShort);
    assert!(!r.implicit_symlinks);
    assert!(matches!(&r.action, Action::Run { binary, .. } if binary == "/bin/echo"));
}

#[test]
fn test_parse_config_from_file_string_and_back() {
    // Round-trip starting from a TOML string
    let original_toml = r#"
[global]
audit_format = "logfmt"
log_tag = "my-ssh-guard"

[flag_groups]
sys-common = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/bin/systemctl", args = ["--no-pager"] }
implicit_symlinks = true
arg_style = "gnu_long"
flag_groups = ["sys-common"]

[[rules.subcommands]]
name = "status"
args = ["{string}.service"]
"#;

    let cfg: config::Config = toml::from_str(original_toml).unwrap();
    let serialized = cfg.to_toml_string().unwrap();
    let reloaded: config::Config = toml::from_str(&serialized).unwrap();

    assert_eq!(reloaded.rules.len(), cfg.rules.len());
    assert_eq!(reloaded.global.audit_format, cfg.global.audit_format);
    assert_eq!(reloaded.flag_groups.len(), cfg.flag_groups.len());
}

// ---------------------------------------------------------------------------
// Template engine + config integration
// ---------------------------------------------------------------------------

#[test]
fn test_template_suffix_in_full_config_flow() {
    // Define a config with contract + template suffix, parse it, verify structure
    let toml_str = r#"
[contracts.unit]
type = "enum"
values = ["angrr", "nix-gc"]

[[rules]]
action = { type = "run", binary = "/bin/systemctl", args = [] }
command = "systemctl"
implicit_symlinks = true

[[rules.subcommands]]
name = "status"
pre_args = ["--no-pager"]
args = ["{unit}.service"]
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.rules.len(), 1);
    let sub = &cfg.rules[0].subcommands[0];
    assert_eq!(sub.name, "status");
    assert_eq!(sub.args, vec!["{unit}.service"]);
    assert_eq!(sub.pre_args, vec!["--no-pager"]);
    assert!(cfg.contracts.contains_key("unit"));
}

#[test]
fn test_mixed_contract_types_in_config() {
    // Config with all three contract types
    let toml_str = r#"
[contracts.port]
type = "int_range"
min = 1024
max = 65535

[contracts.username]
type = "string_len"
min = 3
max = 32

[contracts.svc]
type = "enum"
values = ["ssh", "nginx", "httpd"]

[[rules]]
action = { type = "show_help" }
command = "test"
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.contracts.len(), 3);

    match &cfg.contracts["port"] {
        Contract::IntRange { min, max } => {
            assert_eq!(*min, 1024);
            assert_eq!(*max, 65535);
        }
        _ => panic!("expected IntRange"),
    }
    match &cfg.contracts["username"] {
        Contract::StringLen { min, max } => {
            assert_eq!(*min, 3);
            assert_eq!(*max, 32);
        }
        _ => panic!("expected StringLen"),
    }
    match &cfg.contracts["svc"] {
        Contract::Enum { values } => {
            assert!(values.contains(&"ssh".into()));
        }
        _ => panic!("expected Enum"),
    }
}

#[test]
fn test_nested_subcommands_deep_config() {
    // Three levels of nesting
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/cmd", args = [] }
implicit_symlinks = true

[[rules.subcommands]]
name = "l1"
flags = ["--l1-flag"]

[[rules.subcommands.subcommands]]
name = "l2"
flags = ["--l2-flag"]

[[rules.subcommands.subcommands.subcommands]]
name = "l3"
args = ["{any}"]
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    let r = &cfg.rules[0];
    assert_eq!(r.subcommands.len(), 1);
    let l1 = &r.subcommands[0];
    assert_eq!(l1.name, "l1");
    assert_eq!(l1.flags, vec!["--l1-flag"]);
    assert_eq!(l1.subcommands.len(), 1);
    let l2 = &l1.subcommands[0];
    assert_eq!(l2.name, "l2");
    assert_eq!(l2.flags, vec!["--l2-flag"]);
    assert_eq!(l2.subcommands.len(), 1);
    let l3 = &l2.subcommands[0];
    assert_eq!(l3.name, "l3");
    assert_eq!(l3.args, vec!["{any}"]);
}

// ---------------------------------------------------------------------------
// Flag groups integration
// ---------------------------------------------------------------------------

#[test]
fn test_flag_groups_across_multiple_rules() {
    // flag_groups referenced by rule top-level AND subcommand
    let toml_str = r#"
[flag_groups]
common = ["--no-pager", "--full"]
debug = ["--verbose"]

[[rules]]
action = { type = "run", binary = "/bin/a", args = [] }
flag_groups = ["common"]
flags = ["--extra"]

[[rules.subcommands]]
name = "status"
flag_groups = ["debug"]

[[rules]]
action = { type = "run", binary = "/bin/b", args = [] }
flag_groups = ["common"]
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.flag_groups["common"].len(), 2);
    assert_eq!(cfg.flag_groups["debug"], vec!["--verbose"]);
    assert_eq!(cfg.rules[0].flag_groups, vec!["common"]);
    assert_eq!(cfg.rules[0].subcommands[0].flag_groups, vec!["debug"]);
    assert_eq!(cfg.rules[1].flag_groups, vec!["common"]);
}

// ---------------------------------------------------------------------------
// Arg style propagation
// ---------------------------------------------------------------------------

#[test]
fn test_arg_style_inheritance_in_config() {
    // Parent GnuLong, subcommand inherits, another overrides
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/cmd", args = [] }
arg_style = "gnu_long"

[[rules.subcommands]]
name = "inherited"
# no arg_style -> inherits gnu_long

[[rules.subcommands]]
name = "dos_cmd"
arg_style = "dos"
flags = ["/v"]

[[rules.subcommands]]
name = "posix_cmd"
arg_style = "posix_short"
flags = ["-p"]
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    let r = &cfg.rules[0];
    assert_eq!(r.arg_style, ArgStyle::GnuLong);
    assert_eq!(r.subcommands[0].arg_style, None); // inherits
    assert_eq!(r.subcommands[1].arg_style, Some(ArgStyle::Dos));
    assert_eq!(r.subcommands[2].arg_style, Some(ArgStyle::PosixShort));
}

// ---------------------------------------------------------------------------
// Duration edge cases in full config
// ---------------------------------------------------------------------------

#[test]
fn test_duration_variants_in_full_config() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/a", args = [], timeout = "1.5h" }

[[rules]]
action = { type = "run", binary = "/bin/b", args = [], timeout = "150s" }

[[rules]]
action = { type = "run", binary = "/bin/c", args = [], timeout = 4242 }
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.rules.len(), 3);
}

#[test]
fn test_duration_minutes_and_seconds() {
    // "2m" and "30s" should work fine
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/x", args = [], timeout = "2m" }
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    match &cfg.rules[0].action {
        Action::Run { timeout, .. } => {
            assert_eq!(timeout.millis, 120000);
        }
        _ => panic!("expected Run"),
    }

    let toml_s = r#"
[[rules]]
action = { type = "run", binary = "/bin/x", args = [], timeout = "45s" }
"#;
    let cfg2: config::Config = toml::from_str(toml_s).unwrap();
    match &cfg2.rules[0].action {
        Action::Run { timeout, .. } => {
            assert_eq!(timeout.millis, 45000);
        }
        _ => panic!("expected Run"),
    }
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_config_missing_action_type() {
    let toml_str = r#"
[[rules]]
action = { binary = "/bin/x" }
"#;
    // Missing `type` field in tagged enum
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_invalid_config_bad_duration() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/x", args = [], timeout = "abc" }
"#;
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_invalid_config_unknown_action_type() {
    let toml_str = r#"
[[rules]]
action = { type = "do_something_weird", binary = "/bin/x" }
"#;
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_config_with_empty_subcommands_and_args() {
    // A rule with no subcommands and no args -- just flags
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/bin/uptime", args = [] }
flags = ["--pretty"]
implicit_symlinks = true
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.rules.len(), 1);
    assert_eq!(cfg.rules[0].flags, vec!["--pretty"]);
    assert!(cfg.rules[0].subcommands.is_empty());
    assert!(cfg.rules[0].args.is_empty());
}
