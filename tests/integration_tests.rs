use ssh_guard::config::{
    self, action::Action, arg::ArgStyle, audit::AuditFormat, contract::Contract, rule::Rule,
    subcommand::Subcommand,
};
use std::collections::HashMap;

#[test]
fn test_full_config_round_trip_via_file() {
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
                    binary: "/opt/test/bin/systemctl".into(),
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

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("roundtrip.toml");
    let path_str = config_path.to_str().unwrap();

    cfg.write_to_file(path_str).unwrap();

    let loaded = config::Config::from_file(path_str).unwrap();

    assert_eq!(loaded.rules.len(), 2);
    assert_eq!(loaded.global.audit_log, "/tmp/test-audit.log");
    assert_eq!(loaded.global.audit_format, AuditFormat::Logfmt);
    assert_eq!(loaded.global.help_text, "test help");
    assert_eq!(loaded.flag_groups.len(), 1);
    assert_eq!(loaded.flag_groups["common"].len(), 2);
    assert_eq!(loaded.roots, vec!["/var/log"]);
    assert!(loaded.contracts.contains_key("svc"));

    let r0 = &loaded.rules[0];
    assert_eq!(r0.command_name(), Some("systemctl"));
    assert_eq!(r0.flag_groups, vec!["common"]);
    assert_eq!(r0.flags, vec!["--no-legend"]);
    assert_eq!(r0.subcommands.len(), 1);
    assert_eq!(r0.subcommands[0].name, "status");
    assert_eq!(r0.subcommands[0].arg_style, Some(ArgStyle::Dos));
    assert_eq!(r0.subcommands[0].pre_args, vec!["--no-pager"]);
    assert_eq!(r0.subcommands[0].args, vec!["{string}.service"]);

    let r1 = &loaded.rules[1];
    assert_eq!(r1.command_name(), Some("help"));
    assert!(matches!(r1.action, Action::ShowHelp));
}

#[test]
fn test_full_config_round_trip_via_toml_string() {
    let cfg = config::Config {
        rules: vec![Rule {
            action: Action::Run {
                binary: "/opt/test/bin/echo".into(),
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
    assert!(matches!(&r.action, Action::Run { binary, .. } if binary == "/opt/test/bin/echo"));
}

#[test]
fn test_parse_config_from_file_string_and_back() {
    let original_toml = r#"
[global]
audit_format = "logfmt"
log_tag = "my-ssh-guard"

[flag_groups]
sys-common = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/systemctl", args = ["--no-pager"] }
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

#[test]
fn test_template_suffix_in_full_config_flow() {
    let toml_str = r#"
[contracts.unit]
type = "enum"
values = ["angrr", "nix-gc"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/systemctl", args = [] }
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
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/opt/test/bin/cmd", args = [] }
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

#[test]
fn test_flag_groups_across_multiple_rules() {
    let toml_str = r#"
[flag_groups]
common = ["--no-pager", "--full"]
debug = ["--verbose"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/a", args = [] }
flag_groups = ["common"]
flags = ["--extra"]

[[rules.subcommands]]
name = "status"
flag_groups = ["debug"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/b", args = [] }
flag_groups = ["common"]
"#;

    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.flag_groups["common"].len(), 2);
    assert_eq!(cfg.flag_groups["debug"], vec!["--verbose"]);
    assert_eq!(cfg.rules[0].flag_groups, vec!["common"]);
    assert_eq!(cfg.rules[0].subcommands[0].flag_groups, vec!["debug"]);
    assert_eq!(cfg.rules[1].flag_groups, vec!["common"]);
}

#[test]
fn test_arg_style_inheritance_in_config() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/opt/test/bin/cmd", args = [] }
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

#[test]
fn test_duration_variants_in_full_config() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/a", args = [], timeout = "1.5h" }

[[rules]]
action = { type = "run", binary = "/opt/test/bin/b", args = [], timeout = "150s" }

[[rules]]
action = { type = "run", binary = "/opt/test/bin/c", args = [], timeout = 4242 }
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.rules.len(), 3);
}

#[test]
fn test_duration_minutes_and_seconds() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/x", args = [], timeout = "2m" }
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
action = { type = "run", binary = "/opt/test/bin/x", args = [], timeout = "45s" }
"#;
    let cfg2: config::Config = toml::from_str(toml_s).unwrap();
    match &cfg2.rules[0].action {
        Action::Run { timeout, .. } => {
            assert_eq!(timeout.millis, 45000);
        }
        _ => panic!("expected Run"),
    }
}

#[test]
fn test_invalid_config_missing_action_type() {
    let toml_str = r#"
[[rules]]
action = { binary = "/opt/test/bin/x" }
"#;
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_invalid_config_bad_duration() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/x", args = [], timeout = "abc" }
"#;
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_invalid_config_unknown_action_type() {
    let toml_str = r#"
[[rules]]
action = { type = "do_something_weird", binary = "/opt/test/bin/x" }
"#;
    let result: Result<config::Config, _> = toml::from_str(toml_str);
    assert!(result.is_err());
}

#[test]
fn test_config_with_empty_subcommands_and_args() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/uptime", args = [] }
flags = ["--pretty"]
implicit_symlinks = true
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.rules.len(), 1);
    assert_eq!(cfg.rules[0].flags, vec!["--pretty"]);
    assert!(cfg.rules[0].subcommands.is_empty());
    assert!(cfg.rules[0].args.is_empty());
}

// End-to-end template substitution: match a command, then verify the argv the
// guard would execute has captures resolved from rule-level and subcommand
// templates.

#[test]
fn test_rule_arg_template_substitution_reaches_argv() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/du", args = ["-d{depth:-1}"], timeout = "30s" }
command = "du"
implicit_symlinks = true
arg_style = "gnu_long"
args = ["{path}"]

[contracts.path]
type = "string_len"
min = 1
max = 256
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();

    let argv: Vec<String> = ["du", "/var"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    assert_eq!(matched.rule_index, 0);
    assert_eq!(matched.captures.get("path"), Some(&"/var".to_string()));

    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(built, vec!["-d1".to_string(), "/var".to_string()]);
}

#[test]
fn test_rule_arg_template_missing_capture_fails_closed() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/du", args = ["-d{depth}"], timeout = "30s" }
command = "du"
implicit_symlinks = true
arg_style = "gnu_long"
args = ["{path}"]

[contracts.path]
type = "string_len"
min = 1
max = 256
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();

    // Match succeeds (path captured), but the pinned action arg needs a
    // capture the user never supplied: deny instead of executing with the
    // raw placeholder.
    let argv: Vec<String> = ["du", "/var"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    );
    let err = built.unwrap_err().to_string();
    assert!(err.contains("missing capture 'depth'"), "{err}");
}

#[test]
fn test_contract_validated_depth_passes_through() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/du", args = [], timeout = "30s" }
command = "du"
implicit_symlinks = true
arg_style = "gnu_long"
args = ["-d{depth}", "{path}"]

[contracts.depth]
type = "int_range"
min = 0
max = 3

[contracts.path]
type = "string_len"
min = 1
max = 256
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();

    // In-range depth: match succeeds, user tokens pass through verbatim.
    let argv: Vec<String> = ["du", "-d2", "/var"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    assert_eq!(matched.captures.get("depth"), Some(&"2".to_string()));
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(built, vec!["-d2".to_string(), "/var".to_string()]);

    // Out-of-range depth violates the contract: no match, denied.
    let argv: Vec<String> = ["du", "-d9", "/var"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(ssh_guard::engine::match_command(&cfg, &argv).is_err());
}

#[test]
fn test_issue_regression_du_du_depth() {
    // Regression for the original issue: a rule pinning `du` with
    // action.args = ["-d{du_depth}"] must resolve the placeholder from
    // match captures (or default) at execution time — never pass the raw
    // token `-d{du_depth}` to du (which rejects it as an invalid depth).
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/usr/opt/test/bin/du", args = ["-d{du_depth:-2}"], timeout = "30s" }
command = "du"
implicit_symlinks = true
arg_style = "gnu_long"
args = ["{path}"]

[contracts.path]
type = "string_len"
min = 1
max = 256
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();

    // Substituted pinned value reaches the executed binary's argv:
    // du -d2 /var, not du -d{du_depth:-2} /var.
    let argv: Vec<String> = ["du", "/var"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec!["-d2".to_string(), "/var".to_string()],
        "raw placeholder -d{{du_depth:-2}} must never reach the binary"
    );

    // Missing depth capture with no default: fail closed via denial,
    // never execute with the raw placeholder.
    let toml_str_nodefault = toml_str.replace("{du_depth:-2}", "{du_depth}");
    let cfg2: config::Config = toml::from_str(&toml_str_nodefault).unwrap();
    let matched = ssh_guard::engine::match_command(&cfg2, &argv).unwrap();
    let rule = &cfg2.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    );
    let err = built.unwrap_err().to_string();
    assert!(
        err.contains("missing capture 'du_depth'"),
        "expected missing-capture denial, got: {err}"
    );

    // Contract-validated user capture with the issue's capture name: the
    // rule captures du_depth from the inline flag -d<N> (validated by
    // int_range) and the user token passes through to the binary.
    let toml_str_capture = r#"
[[rules]]
action = { type = "run", binary = "/usr/opt/test/bin/du", args = [], timeout = "30s" }
command = "du"
implicit_symlinks = true
arg_style = "gnu_long"
args = ["-d{du_depth}", "{path}"]

[contracts.du_depth]
type = "int_range"
min = 0
max = 5

[contracts.path]
type = "string_len"
min = 1
max = 256
"#;
    let cfg3: config::Config = toml::from_str(toml_str_capture).unwrap();
    let argv: Vec<String> = ["du", "-d3", "/var"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let matched = ssh_guard::engine::match_command(&cfg3, &argv).unwrap();
    assert_eq!(
        matched.captures.get("du_depth"),
        Some(&"3".to_string()),
        "capture name 'du_depth' must be captured and contract-validated"
    );
    let rule = &cfg3.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec!["-d3".to_string(), "/var".to_string()],
        "contract-validated capture passes through to the binary"
    );

    // Out-of-range depth violates the pinned contract: no match, denied.
    let argv: Vec<String> = ["du", "-d9", "/var"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(ssh_guard::engine::match_command(&cfg3, &argv).is_err());
}

#[test]
fn test_subcommand_pre_args_template_substitution() {
    let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/git", args = [], timeout = "10s" }
command = "git"
implicit_symlinks = true
arg_style = "gnu_long"

[[rules.subcommands]]
name = "remote"
pre_args = ["--namespace={repo:-origin}"]
"#;
    let cfg: config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        cfg.rules[0].subcommands[0].pre_args,
        vec!["--namespace={repo:-origin}"]
    );

    let argv: Vec<String> = ["git", "remote"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec!["remote".to_string(), "--namespace=origin".to_string()]
    );
}

#[test]
fn test_rule_level_pre_args_reach_executed_argv() {
    // Rule-level pre_args (Rule.pre_args, distinct from subcommand
    // pre_args) must be injected into the executed argv — previously they
    // were parsed and validated but silently dropped at execution time.
    let value = toml::toml! {
        [[rules]]
        action = { type = "run", binary = "/opt/test/bin/du", args = [], timeout = "30s" }
        command = "du"
        implicit_symlinks = true
        arg_style = "gnu_long"
        pre_args = ["--one-file-system", "--human-readable"]
        args = ["{path}"]

        [contracts.path]
        type = "string_len"
        min = 1
        max = 256
    };
    let cfg: config::Config = value.try_into().unwrap();
    assert_eq!(
        cfg.rules[0].pre_args,
        vec!["--one-file-system", "--human-readable"]
    );

    // Plain literal rule-level pre_args land before user argv.
    let argv: Vec<String> = ["du", "/var"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec![
            "--one-file-system".to_string(),
            "--human-readable".to_string(),
            "/var".to_string(),
        ],
        "rule-level pre_args must appear in the executed argv before user args"
    );
}

#[test]
fn test_rule_level_pre_args_ordered_before_subcommand_pre_args() {
    // Ordering: action.args -> rule pre_args -> subcommand name ->
    // subcommand pre_args -> user argv. Rule-level pre_args are
    // top-level flags, so they must come before any injected
    // subcommand name.
    let value = toml::toml! {
        [[rules]]
        action = { type = "run", binary = "/opt/test/bin/git", args = ["--exec-path=/opt/git"], timeout = "10s" }
        command = "git"
        implicit_symlinks = true
        arg_style = "gnu_long"
        pre_args = ["--no-pager"]

        [[rules.subcommands]]
        name = "log"
        pre_args = ["--graph"]
    };
    let cfg: config::Config = value.try_into().unwrap();

    let argv: Vec<String> = ["git", "log"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec![
            "--exec-path=/opt/git".to_string(), // action.args
            "--no-pager".to_string(),           // rule-level pre_args
            "log".to_string(),                  // subcommand name
            "--graph".to_string(),              // subcommand pre_args
        ],
        "rule-level pre_args must precede the subcommand name and user argv"
    );
}

#[test]
fn test_rule_level_pre_args_template_substitution() {
    // Rule-level pre_args support the same {name} / {name:-default}
    // placeholder substitution as action.args and subcommand pre_args,
    // failing closed on a missing capture with no default.
    let value = toml::toml! {
        [[rules]]
        action = { type = "run", binary = "/opt/test/bin/git", args = [], timeout = "10s" }
        command = "git"
        implicit_symlinks = true
        arg_style = "gnu_long"
        pre_args = ["-c", "safe.directory={repo:-*}"]
        args = ["{path}"]

        [contracts.path]
        type = "string_len"
        min = 1
        max = 256
    };
    let cfg: config::Config = value.clone().try_into().unwrap();

    // No capture named 'repo' -> the default applies.
    let argv: Vec<String> = ["git", "/srv/repo"].iter().map(|s| s.to_string()).collect();
    let matched = ssh_guard::engine::match_command(&cfg, &argv).unwrap();
    let rule = &cfg.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    )
    .unwrap();
    assert_eq!(
        built,
        vec![
            "-c".to_string(),
            "safe.directory=*".to_string(),
            "/srv/repo".to_string(),
        ]
    );

    // A config without the default must deny the placeholder fail-closed.
    let mut cfg2: config::Config = value.try_into().unwrap();
    cfg2.rules[0].pre_args = vec!["-c".to_string(), "safe.directory={repo}".to_string()];
    let matched = ssh_guard::engine::match_command(&cfg2, &argv).unwrap();
    let rule = &cfg2.rules[matched.rule_index];
    let built = ssh_guard::actions::execute_argv_for_test(
        rule,
        &matched.subcommand_path,
        &matched.captures,
        &argv,
    );
    let err = built.unwrap_err().to_string();
    assert!(
        err.contains("missing capture 'repo'"),
        "expected missing-capture denial, got: {err}"
    );
}
