use std::collections::HashMap;

use super::flags::{effective_style, expand_flags, is_flag_like};
use super::parse::parse_arg_pattern;
use super::types::{ArgPattern, MatchResult, TemplateType};
use super::validate::validate_template_value;
use crate::config::{Config, rule::Rule, subcommand::Subcommand};
use crate::errors::{GuardError, MatchFailure};

pub fn match_command(config: &Config, argv: &[String]) -> Result<MatchResult, GuardError> {
    let mut all_failures: Vec<MatchFailure> = Vec::new();

    for (rule_idx, rule) in config.rules.iter().enumerate() {
        let mut failures: Vec<MatchFailure> = Vec::new();

        if let Ok(result) = try_match_rule(rule_idx, rule, config, argv, &mut failures) {
            return Ok(result);
        }

        all_failures.append(&mut failures);
    }

    Err(GuardError::NoMatch {
        command: argv.join(" "),
        failures: all_failures,
    })
}

pub(crate) fn record_failure(
    failures: &mut Vec<MatchFailure>,
    rule_idx: usize,
    path: &[String],
    at_token: usize,
    token: &str,
    reason: &str,
) {
    failures.push(MatchFailure {
        rule_index: rule_idx,
        subcommand_path: path.to_vec(),
        at_token,
        token: token.to_string(),
        reason: reason.to_string(),
    });
}

pub(crate) fn try_match_rule(
    rule_idx: usize,
    rule: &Rule,
    config: &Config,
    argv: &[String],
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchResult, ()> {
    if argv.is_empty() {
        record_failure(failures, rule_idx, &[], 0, "", "empty command");
        return Err(());
    }

    // Resolve command name and match argv[0]
    let mut start = 0;
    if let Some(cmd) = rule.command_name() {
        if argv[0] != cmd {
            // Not a direct name match. Check if argv[0] resolves via symlink
            // to the same real file as the rule's binary.
            let symlink_match = rule.binary_path().and_then(|bin| {
                let user_real = std::fs::canonicalize(&argv[0]).ok()?;
                let rule_real = std::fs::canonicalize(bin).ok()?;
                if user_real == rule_real {
                    Some(())
                } else {
                    None
                }
            });
            if symlink_match.is_none() {
                record_failure(
                    failures,
                    rule_idx,
                    &[],
                    0,
                    &argv[0],
                    &format!("expected '{}'", cmd),
                );
                return Err(());
            }
        }
        start = 1;
    }

    // Consume top-level flags
    let top_flags = expand_flags(&config.flag_groups, &rule.flag_groups, &rule.flags);
    let style = &rule.arg_style;
    let i = consume_flags(argv, start, &top_flags, style, rule_idx, &[], failures);

    if i >= argv.len() {
        // All tokens consumed. If the rule has nothing to match against,
        // this is fine (e.g., "help" with no args).
        if rule.subcommands.is_empty() && rule.args.is_empty() {
            return Ok(MatchResult {
                rule_index: rule_idx,
                captures: HashMap::new(),
                subcommand_path: vec![],
            });
        }
        let last = argv.last().map(|s| s.as_str()).unwrap_or("");
        record_failure(
            failures,
            rule_idx,
            &[],
            argv.len().saturating_sub(1),
            last,
            "no arguments after command",
        );
        return Err(());
    }

    // Branch: subcommands present vs rule-level args
    if !rule.subcommands.is_empty() {
        walk_subcommands(rule_idx, rule, config, argv, i, &[], failures)
    } else if !rule.args.is_empty() {
        match_remaining_args_inner(rule_idx, config, argv, i, &[], &rule.args, style, failures)
    } else {
        // No subcommands and no args — unexpected remaining tokens
        record_failure(
            failures,
            rule_idx,
            &[],
            i,
            &argv[i],
            "unexpected arguments after command",
        );
        Err(())
    }
}

pub(crate) fn consume_flags(
    argv: &[String],
    start: usize,
    allowed: &[String],
    style: &crate::config::arg::ArgStyle,
    _rule_idx: usize,
    _path: &[String],
    _failures: &mut Vec<MatchFailure>,
) -> usize {
    let mut i = start;
    while i < argv.len() {
        let token = &argv[i];

        // Exact match — consume regardless of style
        if allowed.contains(token) {
            i += 1;
            // Consume value token if next is non-flag
            if i < argv.len() && !is_flag_like(&argv[i], style) {
                i += 1;
            }
            continue;
        }

        // Inline value: --flag=value or /flag:value
        let sep = if matches!(style, crate::config::arg::ArgStyle::Dos) {
            ':'
        } else {
            '='
        };
        if let Some(sep_pos) = token.find(sep) {
            let flag_part = &token[..sep_pos];
            if allowed.contains(&flag_part.to_string()) {
                i += 1;
                continue;
            }
        }

        // Not in allowed list or matching inline template — stop.
        // This token may be an inline arg template (--depth=5) or
        // a positional arg. Let match_remaining_args handle it.
        break;
    }
    i
}

pub(crate) fn walk_subcommands(
    rule_idx: usize,
    rule: &Rule,
    config: &Config,
    argv: &[String],
    start: usize,
    path: &[String],
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchResult, ()> {
    let token = &argv[start];

    for sub in &rule.subcommands {
        if sub.name != *token {
            continue;
        }

        let mut new_path = path.to_vec();
        new_path.push(sub.name.clone());
        let mut i = start + 1;

        // Consume this subcommand's flags
        let sub_style = effective_style(rule, Some(sub));
        let sub_flags = expand_flags(&config.flag_groups, &sub.flag_groups, &sub.flags);
        i = consume_flags(
            argv, i, &sub_flags, sub_style, rule_idx, &new_path, failures,
        );

        // Check nested subcommands
        if !sub.subcommands.is_empty() && i < argv.len() {
            // Peek at next token — if it matches a nested subcommand, descend
            if sub.subcommands.iter().any(|n| n.name == argv[i]) {
                return walk_subcommands_nested(
                    rule_idx, rule, config, argv, i, &new_path, sub, failures,
                );
            }
        }

        // No more nesting — match remaining as args
        return match_remaining_args(rule_idx, config, argv, i, &new_path, sub, failures);
    }

    record_failure(failures, rule_idx, path, start, token, "unknown subcommand");
    Err(())
}

pub(crate) fn walk_subcommands_nested(
    rule_idx: usize,
    rule: &Rule,
    config: &Config,
    argv: &[String],
    start: usize,
    path: &[String],
    parent: &Subcommand,
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchResult, ()> {
    let token = &argv[start];

    for sub in &parent.subcommands {
        if sub.name != *token {
            continue;
        }

        let mut new_path = path.to_vec();
        new_path.push(sub.name.clone());
        let mut i = start + 1;

        let sub_style = effective_style(rule, Some(sub));
        let sub_flags = expand_flags(&config.flag_groups, &sub.flag_groups, &sub.flags);
        i = consume_flags(
            argv, i, &sub_flags, sub_style, rule_idx, &new_path, failures,
        );

        // Deeper nesting?
        if !sub.subcommands.is_empty() && i < argv.len() {
            if sub.subcommands.iter().any(|n| n.name == argv[i]) {
                return walk_subcommands_nested(
                    rule_idx, rule, config, argv, i, &new_path, sub, failures,
                );
            }
        }

        return match_remaining_args(rule_idx, config, argv, i, &new_path, sub, failures);
    }

    record_failure(
        failures,
        rule_idx,
        path,
        start,
        token,
        "unknown nested subcommand",
    );
    Err(())
}

pub(crate) fn match_remaining_args_inner(
    rule_idx: usize,
    config: &Config,
    argv: &[String],
    start: usize,
    path: &[String],
    args: &[String],
    style: &crate::config::arg::ArgStyle,
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchResult, ()> {
    let mut captures: HashMap<String, String> = HashMap::new();
    let mut arg_counter: usize = 0;

    let patterns: Vec<ArgPattern> = args.iter().map(|a| parse_arg_pattern(a)).collect();

    let mut i = start;
    let mut has_error = false;

    while i < argv.len() {
        let token = &argv[i];
        let mut matched = false;

        for pattern in &patterns {
            match pattern {
                ArgPattern::Literal(lit) => {
                    if token == lit {
                        matched = true;
                        i += 1;
                        break;
                    }
                }
                ArgPattern::InlineFlag { flag, template } => {
                    let sep = if matches!(style, crate::config::arg::ArgStyle::Dos) {
                        ':'
                    } else {
                        '='
                    };
                    let prefix = format!("{flag}{sep}");
                    if token.starts_with(&prefix) {
                        let value = &token[prefix.len()..];
                        let cap_name = capture_name(template, &mut arg_counter);
                        if let Err(reason) =
                            validate_template_value(value, template, &config.contracts)
                        {
                            record_failure(failures, rule_idx, path, i, token, &reason);
                            has_error = true;
                            // Still advance — collect all errors
                        }
                        captures.insert(cap_name, value.to_string());
                        matched = true;
                        i += 1;
                        break;
                    }
                }
                ArgPattern::Template(template) => {
                    // Positional — matches any non-flag token
                    if !is_flag_like(token, style) {
                        let cap_name = capture_name(template, &mut arg_counter);
                        if let Err(reason) =
                            validate_template_value(token, template, &config.contracts)
                        {
                            record_failure(failures, rule_idx, path, i, token, &reason);
                            has_error = true;
                        }
                        captures.insert(cap_name, token.to_string());
                        matched = true;
                        i += 1;
                        break;
                    }
                }
                ArgPattern::TemplateContext {
                    prefix,
                    suffix,
                    template,
                } => {
                    let mut works = true;
                    if let Some(p) = prefix {
                        if !token.starts_with(p.as_str()) {
                            works = false;
                        }
                    }
                    if let Some(s) = suffix {
                        if !token.ends_with(s.as_str()) {
                            works = false;
                        }
                    }
                    if works {
                        let base_start = prefix.as_ref().map_or(0, |p| p.len());
                        let base_end = token.len() - suffix.as_ref().map_or(0, |s| s.len());
                        if base_start < base_end {
                            let base = &token[base_start..base_end];
                            let cap_name = capture_name(template, &mut arg_counter);
                            if let Err(reason) =
                                validate_template_value(base, template, &config.contracts)
                            {
                                record_failure(failures, rule_idx, path, i, token, &reason);
                                has_error = true;
                            }
                            captures.insert(cap_name, base.to_string());
                            matched = true;
                            i += 1;
                            break;
                        }
                    }
                }
            }
        }

        if !matched {
            record_failure(failures, rule_idx, path, i, token, "not in allowed args");
            has_error = true;
            i += 1;
        }
    }

    if has_error {
        Err(())
    } else {
        Ok(MatchResult {
            rule_index: rule_idx,
            captures,
            subcommand_path: path.to_vec(),
        })
    }
}

pub(crate) fn match_remaining_args(
    rule_idx: usize,
    config: &Config,
    argv: &[String],
    start: usize,
    path: &[String],
    subcommand: &Subcommand,
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchResult, ()> {
    let style = effective_style(&config.rules[rule_idx], Some(subcommand));
    match_remaining_args_inner(
        rule_idx,
        config,
        argv,
        start,
        path,
        &subcommand.args,
        style,
        failures,
    )
}

pub(crate) fn capture_name(template: &TemplateType, counter: &mut usize) -> String {
    match template {
        TemplateType::ContractRef(name) => name.clone(),
        _ => {
            let n = *counter;
            *counter += 1;
            format!("arg_{n}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::arg::ArgStyle;
    use crate::config::{
        Config, action::Action, contract::Contract, duration::Duration, rule::Rule,
        subcommand::Subcommand,
    };
    use crate::errors::GuardError;
    use std::collections::HashMap;

    fn make_config() -> Config {
        Config {
            contracts: {
                let mut c = HashMap::new();
                c.insert(
                    "port".into(),
                    Contract::IntRange {
                        min: 1024,
                        max: 65535,
                    },
                );
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
                f.insert("git-common".into(), vec!["--no-pager".into()]);
                f
            },
            rules: vec![
                // Rule 0 — git
                Rule {
                    action: Action::Run {
                        binary: "/run/current-system/sw/bin/git".into(),
                        args: vec![],
                        timeout: Duration { millis: 5000 },
                    },
                    command: Some("git".into()),
                    args: vec![],
                    pre_args: vec![],
                    implicit_symlinks: true,
                    arg_style: ArgStyle::GnuLong,
                    flag_groups: vec![],
                    flags: vec!["-C".into()],
                    subcommands: vec![
                        Subcommand {
                            name: "status".into(),
                            arg_style: None,
                            flag_groups: vec!["git-common".into()],
                            flags: vec![],
                            args: vec!["--porcelain".into(), "--short".into(), "{string}".into()],
                            pre_args: vec![],
                            subcommands: vec![],
                        },
                        Subcommand {
                            name: "log".into(),
                            arg_style: None,
                            flag_groups: vec![],
                            flags: vec!["--oneline".into()],
                            args: vec!["{int}".into()],
                            pre_args: vec![],
                            subcommands: vec![],
                        },
                        Subcommand {
                            name: "clone".into(),
                            arg_style: None,
                            flag_groups: vec![],
                            flags: vec![],
                            args: vec![
                                "--depth={int}".into(),
                                "--branch={string}".into(),
                                "{any}".into(),
                            ],
                            pre_args: vec![],
                            subcommands: vec![],
                        },
                        Subcommand {
                            name: "remote".into(),
                            arg_style: None,
                            flag_groups: vec![],
                            flags: vec![],
                            args: vec![],
                            pre_args: vec![],
                            subcommands: vec![Subcommand {
                                name: "add".into(),
                                arg_style: None,
                                flag_groups: vec![],
                                flags: vec![],
                                args: vec!["{string}".into()],
                                pre_args: vec![],
                                subcommands: vec![],
                            }],
                        },
                    ],
                },
                // Rule 1 — help
                Rule {
                    action: Action::ShowHelp,
                    command: Some("help".into()),
                    args: vec![],
                    pre_args: vec![],
                    implicit_symlinks: true,
                    arg_style: ArgStyle::GnuLong,
                    flag_groups: vec![],
                    flags: vec![],
                    subcommands: vec![],
                },
            ],
            roots: vec!["/var/log".into()],
            units: vec!["sshd.service".into()],
            ..Default::default()
        }
    }

    // --- Basic matching ---

    #[test]
    fn test_match_help() {
        let cfg = make_config();
        let argv = vec!["help".to_string()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 1);
        assert_eq!(result.subcommand_path, Vec::<String>::new());
    }

    #[test]
    fn test_match_status_simple() {
        let cfg = make_config();
        let argv = vec!["git".to_string(), "status".to_string()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["status"]);
    }

    #[test]
    fn test_match_status_with_flag() {
        let cfg = make_config();
        let argv = vec!["git".into(), "status".into(), "--porcelain".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
    }

    #[test]
    fn test_match_status_with_flag_group() {
        let cfg = make_config();
        let argv = vec!["git".into(), "status".into(), "--no-pager".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
    }

    #[test]
    fn test_match_status_with_positional() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "status".into(),
            "--porcelain".into(),
            "myfile.txt".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.captures.get("arg_0").unwrap(), "myfile.txt");
    }

    #[test]
    fn test_match_clone() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "clone".into(),
            "--depth=5".into(),
            "--branch=main".into(),
            "https://example.com/repo".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.captures.get("arg_0").unwrap(), "5");
        assert_eq!(result.captures.get("arg_1").unwrap(), "main");
        assert_eq!(
            result.captures.get("arg_2").unwrap(),
            "https://example.com/repo"
        );
    }

    #[test]
    fn test_match_log_with_int() {
        let cfg = make_config();
        let argv = vec!["git".into(), "log".into(), "--oneline".into(), "10".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
    }

    // --- Nested subcommands ---

    #[test]
    fn test_match_nested_subcommand() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "remote".into(),
            "add".into(),
            "user/repo".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["remote", "add"]);
        assert_eq!(result.captures.get("arg_0").unwrap(), "user/repo");
    }

    // --- Flags scoped (not recursive) ---

    #[test]
    fn test_flags_scoped_not_recursive() {
        let cfg = make_config();
        let argv = vec!["git".into(), "status".into(), "--oneline".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(!failures.is_empty());
                assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Top-level flags ---

    #[test]
    fn test_top_level_flags() {
        let cfg = make_config();
        let argv = vec!["git".into(), "-C".into(), "/tmp".into(), "status".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["status"]);
    }

    // --- Unknown subcommand ---

    #[test]
    fn test_unknown_subcommand() {
        let cfg = make_config();
        let argv = vec!["bogus".to_string()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason.contains("expected")));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Collect all failures ---

    #[test]
    fn test_rich_errors_multiple_failures() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "status".into(),
            "--unknown".into(),
            "extra".into(),
        ];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(!failures.is_empty());
                assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Contract validation ---

    #[test]
    fn test_contract_int_range_ok() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("bind".into()),
            args: vec!["{port}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["bind".into(), "8080".into()];
        assert!(match_command(&cfg, &argv).is_ok());
    }

    #[test]
    fn test_contract_int_range_fail() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("bind".into()),
            args: vec!["{port}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["bind".into(), "80".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason.contains("not in range")));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn test_contract_enum_ok() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("svc-check".into()),
            args: vec!["{svc}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["svc-check".into(), "ssh".into()];
        assert!(match_command(&cfg, &argv).is_ok());
    }

    #[test]
    fn test_contract_enum_fail() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("svc-check".into()),
            args: vec!["{svc}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["svc-check".into(), "ftp".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason.contains("not in")));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Template suffix matching ---

    #[test]
    fn test_match_template_suffix_enum_ok() {
        let mut cfg2 = make_config();
        cfg2.rules[0].subcommands[0].args = vec!["{string}.service".into()];
        let argv = vec!["git".into(), "status".into(), "angrr.service".into()];
        let result = match_command(&cfg2, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0"), Some(&"angrr".to_string()));
    }

    #[test]
    fn test_match_template_suffix_enum_contract_ok() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["angrr".into(), "nix-gc".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["{unit}.service".into()];
        let argv = vec!["git".into(), "status".into(), "angrr.service".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("unit"), Some(&"angrr".to_string()));
    }

    #[test]
    fn test_match_template_suffix_enum_contract_fail() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["angrr".into(), "nix-gc".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["{unit}.service".into()];
        let argv = vec!["git".into(), "status".into(), "bad.service".into()];
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
    }

    #[test]
    fn test_match_template_suffix_no_suffix() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["angrr".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["{unit}.service".into()];
        let result = match_command(&cfg, &["git".into(), "status".into(), "angrr".into()]);
        assert!(result.is_err());
    }

    // --- Template context matching ---

    #[test]
    fn test_match_template_context_prefix_ok() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["sshd".into(), "nginx".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["--{unit}".into()];
        let argv = vec!["git", "status", "--sshd"];
        let result = match_command(
            &cfg,
            &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(result.captures.get("unit"), Some(&"sshd".to_string()));
    }

    #[test]
    fn test_match_template_context_both_sides_ok() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["sshd".into(), "nginx".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["--unit.{unit}.timer".into()];
        let argv = vec!["git", "status", "--unit.sshd.timer"];
        let result = match_command(
            &cfg,
            &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(result.captures.get("unit"), Some(&"sshd".to_string()));
    }

    #[test]
    fn test_match_template_context_prefix_fail_bad_value() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["sshd".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["--{unit}".into()];
        let argv: Vec<String> = vec!["git", "status", "--bad"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
    }

    #[test]
    fn test_match_template_context_prefix_no_match() {
        let mut cfg = make_config();
        cfg.contracts.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["sshd".into()],
            },
        );
        cfg.rules[0].subcommands[0].args = vec!["--{unit}".into()];
        let argv: Vec<String> = vec!["git", "status", "sshd"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
    }

    // --- Matching with Arg Style Override ---

    #[test]
    fn test_match_dos_subcommand_flags() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("tool".into()),
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![Subcommand {
                name: "run".into(),
                arg_style: Some(ArgStyle::Dos),
                flag_groups: vec![],
                flags: vec!["/verbose".into()],
                args: vec!["{string}".into()],
                pre_args: vec![],
                subcommands: vec![],
            }],
        });
        let argv = vec![
            "tool".into(),
            "run".into(),
            "/verbose".into(),
            "val".into(),
            "stuff".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "stuff");
    }

    #[test]
    fn test_match_posix_short_flags() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("tool".into()),
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![Subcommand {
                name: "run".into(),
                arg_style: Some(ArgStyle::PosixShort),
                flag_groups: vec![],
                flags: vec!["-f".into()],
                args: vec!["{string}".into()],
                pre_args: vec![],
                subcommands: vec![],
            }],
        });
        let argv = vec![
            "tool".into(),
            "run".into(),
            "-f".into(),
            "val".into(),
            "stuff".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "stuff");
    }

    #[test]
    fn test_match_mixed_styles() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("tool".into()),
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![Subcommand {
                name: "run".into(),
                arg_style: Some(ArgStyle::Dos),
                flag_groups: vec![],
                flags: vec!["--gnu-flag".into(), "/dos-flag".into()],
                args: vec!["{string}".into(), "{string}".into()],
                pre_args: vec![],
                subcommands: vec![],
            }],
        });
        let argv = vec![
            "tool".into(),
            "run".into(),
            "--gnu-flag".into(),
            "val1".into(),
            "/dos-flag".into(),
            "val2".into(),
            "args".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "args");
    }

    // --- Flag and Subcommand Order Tests ---

    #[test]
    fn test_match_flags_before_subcommand() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "-C".into(),
            "/tmp".into(),
            "status".into(),
            "--porcelain".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["status"]);
    }

    #[test]
    fn test_match_flags_after_subcommand_before_args() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "status".into(),
            "--porcelain".into(),
            "myfile".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.subcommand_path, vec!["status"]);
        assert_eq!(result.captures.get("arg_0").unwrap(), "myfile");
    }

    #[test]
    fn test_match_flags_interleaved() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "status".into(),
            "--porcelain".into(),
            "myfile".into(),
            "--unknown".into(),
        ];
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
    }

    // --- Template Context Edge Cases ---

    #[test]
    fn test_match_template_context_exact_boundary() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("test".into()),
            args: vec!["--{int}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["test".into(), "--42abc".into()];
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
        let argv2 = vec!["test".into(), "--42".into()];
        let result2 = match_command(&cfg, &argv2);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().captures.get("arg_0").unwrap(), "42");
    }

    // --- Error Collection ---

    #[test]
    fn test_multiple_validation_failures() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("check".into()),
            args: vec!["{port}".into(), "{port}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["check".into(), "80".into(), "99999".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(
                    failures.len() >= 2,
                    "expected at least 2 failures, got {failures:?}"
                );
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn test_match_command_empty_argv() {
        let cfg = make_config();
        let argv: Vec<String> = vec![];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(!failures.is_empty());
                assert!(failures.iter().any(|f| f.reason == "empty command"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Rule with no command_name (command=None, non-Run action) ---

    #[test]
    fn test_rule_no_command() {
        let mut cfg = make_config();
        // Rule with command=None and a subcommand, command_name() returns None,
        // so the command-name check is skipped (covers the None branch at match L73).
        // argv[0] matches the subcommand name.
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: None,
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![Subcommand {
                name: "any-tool".into(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            }],
        });
        let argv = vec!["any-tool".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 2);
        assert_eq!(result.subcommand_path, vec!["any-tool"]);
    }

    // --- No subcommand / arg after flags consumed ---

    #[test]
    fn test_no_args_after_command_with_subcommands() {
        // Rule has subcommands but argv is just the command name
        let cfg = make_config();
        let argv = vec!["git".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason == "no arguments after command")
                );
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn test_unexpected_arguments_no_subcommands_no_args() {
        // Rule has no subcommands and no args -- extra tokens are unexpected
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("simple".into()),
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["simple".into(), "extra".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason.contains("unexpected")));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Dos style inline flag consumption in consume_flags ---

    #[test]
    fn test_consume_flags_dos_inline() {
        let mut cfg = make_config();
        // Dos-style inline flag consumption: /flag:value uses ':' as separator.
        // Flag must be at the level where consume_flags runs here, as a top-level
        // flag before the subcommand. This covers the inline consumption in consume_flags (L153-154).
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("dos-tool".into()),
            args: vec![],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::Dos,
            flag_groups: vec![],
            flags: vec!["/verbose".into()],
            subcommands: vec![Subcommand {
                name: "run".into(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec!["{string}".into()],
                pre_args: vec![],
                subcommands: vec![],
            }],
        });
        // /verbose:true before subcommand - consumed at top-level by consume_flags
        let argv = vec![
            "dos-tool".into(),
            "/verbose:true".into(),
            "run".into(),
            "data".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "data");
    }

    // --- walk_subcommands: token doesn't match any subcommand ---

    #[test]
    fn test_walk_subcommands_token_not_found() {
        let cfg = make_config();
        // "git bogus" - "bogus" is not a subcommand of git
        let argv = vec!["git".into(), "bogus".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason == "unknown subcommand"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- walk_subcommands_nested: matched nested subcommand with remaining args ---

    #[test]
    fn test_walk_subcommands_nested_with_args() {
        // Tests walk_subcommands_nested matching a nested subcommand and then
        // dispatching to match_remaining_args. Covers the deeper nesting path
        // in walk_subcommands_nested (L240-258).
        // "git remote add my-remote" - remote->add is a nested subcommand with args [{string}]
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "remote".into(),
            "add".into(),
            "my-remote".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["remote", "add"]);
        assert_eq!(result.captures.get("arg_0").unwrap(), "my-remote");
    }

    // --- InlineFlag with Dos style separator in match_remaining_args_inner ---

    #[test]
    fn test_inline_flag_dos_separator_in_args() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("dos-args".into()),
            args: vec!["/level:{int}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::Dos,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["dos-args".into(), "/level:5".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "5");
    }

    // --- TemplateContext: empty capture (base_start >= base_end) ---

    #[test]
    fn test_template_context_empty_capture() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("t-empty".into()),
            // Pattern prefix="--", suffix=None
            args: vec!["--{int}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        // "--" gives base_start=2, base_end=2 → 2 < 2 → false, no capture
        let argv = vec!["t-empty".into(), "--".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- TemplateContext: prefix matches but suffix doesn't ---

    #[test]
    fn test_template_context_suffix_mismatch() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("t-suffix".into()),
            args: vec!["--{string}.service".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        // prefix="--" matches, suffix=".service" doesn't match "--foo.bad"
        let argv = vec!["t-suffix".into(), "--foo.bad".into()];
        let err = match_command(&cfg, &argv).unwrap_err();
        match err {
            GuardError::NoMatch { failures, .. } => {
                assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
            }
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    // --- Rule-level args (no subcommands) ---

    #[test]
    fn test_rule_level_args_no_subcommands() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("direct".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["direct".into(), "value".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "value");
    }

    // --- Dos-style InlineFlag in match_remaining_args_inner ---

    #[test]
    fn test_inline_flag_dos_colon_separator() {
        // Covers the ':' separator branch in InlineFlag match (Dos style)
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("dos-inline".into()),
            args: vec!["/depth:{int}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::Dos,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        });
        let argv = vec!["dos-inline".into(), "/depth:10".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "10");
    }
}
