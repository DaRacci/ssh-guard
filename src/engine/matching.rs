use std::collections::HashMap;

use super::flags::{effective_style, expand_flags, is_flag_like};
use super::parse::parse_arg_pattern;
use super::types::{ArgPattern, MatchResult, TemplateType};
use super::validate::validate_template_value;
use crate::config::arg::ArgStyle;
use crate::config::{Config, rule::Rule, subcommand::Subcommand};
use crate::errors::{GuardError, MatchFailure};

/// Match user argv against configured rule tree.
///
/// # Errors
///
/// Returns `GuardError::NoMatch` when no rule matches `argv`.
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

/// Successful match state threaded through the recursive matcher.
#[derive(Clone)]
struct MatchState {
    captures: HashMap<String, String>,
    arg_counter: usize,

    /// Subcommand path of the deepest level reached so far.
    path: Vec<String>,

    /// A template value failed validation, the match must ultimately fail even if every token is consumed.
    had_validation_error: bool,

    /// True once an arg pattern or subcommand consumed a token.
    /// Top-level rules that declare args or subcommands require at least one such match.
    consumed_arg_or_sub: bool,
}

/// One matcher level: the flags, arg patterns, and subcommands declared by
/// the rule itself or by the subcommand we have descended into.
struct LevelCtx<'a> {
    rule: &'a Rule,
    config: &'a Config,
    flags: Vec<String>,
    patterns: Vec<ArgPattern>,
    subcommands: &'a [Subcommand],
    style: &'a ArgStyle,
    path: Vec<String>,
    is_top_level: bool,
}

impl<'a> LevelCtx<'a> {
    fn for_rule(rule: &'a Rule, config: &'a Config) -> LevelCtx<'a> {
        LevelCtx {
            rule,
            config,
            flags: expand_flags(&config.flag_groups, &rule.flag_groups, &rule.flags),
            patterns: rule.args.iter().map(|a| parse_arg_pattern(a)).collect(),
            subcommands: &rule.subcommands,
            style: &rule.arg_style,
            path: Vec::new(),
            is_top_level: true,
        }
    }

    fn for_sub(parent: &LevelCtx<'a>, sub: &'a Subcommand) -> LevelCtx<'a> {
        let mut path = parent.path.clone();
        path.push(sub.name.clone());
        LevelCtx {
            rule: parent.rule,
            config: parent.config,
            flags: expand_flags(&parent.config.flag_groups, &sub.flag_groups, &sub.flags),
            patterns: sub.args.iter().map(|a| parse_arg_pattern(a)).collect(),
            subcommands: &sub.subcommands,
            style: effective_style(parent.rule, Some(sub)),
            path,
            is_top_level: false,
        }
    }
}

fn sep_for(style: &ArgStyle) -> char {
    if matches!(style, ArgStyle::Dos) {
        ':'
    } else {
        '='
    }
}

fn fail_reason(ctx: &LevelCtx) -> &'static str {
    if !ctx.subcommands.is_empty() {
        if ctx.is_top_level {
            "unknown subcommand"
        } else {
            "not in allowed args"
        }
    } else if ctx.patterns.is_empty() && ctx.is_top_level {
        "unexpected arguments after command"
    } else {
        "not in allowed args"
    }
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
                    &format!("expected '{cmd}'"),
                );
                return Err(());
            }
        }
        start = 1;
    }

    if start >= argv.len() {
        // All tokens consumed - fine if rule has nothing left to match
        if rule.subcommands.is_empty() && rule.args.is_empty() {
            return Ok(MatchResult {
                rule_index: rule_idx,
                captures: HashMap::new(),
                subcommand_path: vec![],
            });
        }
        let last = argv.last().map_or("", String::as_str);
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

    let ctx = LevelCtx::for_rule(rule, config);
    let state = MatchState {
        captures: HashMap::new(),
        arg_counter: 0,
        path: Vec::new(),
        had_validation_error: false,
        consumed_arg_or_sub: false,
    };

    match match_level(&ctx, rule_idx, argv, start, state, failures) {
        Ok(state) if !state.had_validation_error => Ok(MatchResult {
            rule_index: rule_idx,
            captures: state.captures,
            subcommand_path: state.path,
        }),
        _ => Err(()),
    }
}

/// Consumes argv left to right, accepting allowlisted flags, positional arg patterns, and subcommand descent in any order.
/// Branches backtrack on dead ends.
fn match_level(
    ctx: &LevelCtx,
    rule_idx: usize,
    argv: &[String],
    pos: usize,
    state: MatchState,
    failures: &mut Vec<MatchFailure>,
) -> Result<MatchState, ()> {
    if pos >= argv.len() {
        // A top-level rule declaring args or subcommands needs at least one token matched by an arg pattern or subcommand descent.
        // Failing here lets the caller backtrack into other branches.
        if ctx.is_top_level
            && (!ctx.subcommands.is_empty() || !ctx.patterns.is_empty())
            && !state.consumed_arg_or_sub
        {
            let last = argv.last().map_or("", String::as_str);
            record_failure(
                failures,
                rule_idx,
                &ctx.path,
                argv.len().saturating_sub(1),
                last,
                "no arguments after command",
            );
            return Err(());
        }
        return Ok(state);
    }
    let token = &argv[pos];

    // Exact allowlisted flag with token shape
    if ctx.flags.iter().any(|f| f == token) {
        // Greedy "flag value" consumption first then standalone
        if pos + 1 < argv.len()
            && !is_flag_like(&argv[pos + 1], ctx.style)
            && let Ok(next) = match_level(ctx, rule_idx, argv, pos + 2, state.clone(), failures)
        {
            return Ok(next);
        }
        if let Ok(next) = match_level(ctx, rule_idx, argv, pos + 1, state.clone(), failures) {
            return Ok(next);
        }
        // Fall through, the token may also be matched by an arg pattern
    }

    if is_flag_like(token, ctx.style) {
        // Inline value form
        let sep = sep_for(ctx.style);
        if let Some(sep_pos) = token.find(sep)
            && ctx.flags.iter().any(|f| *f == token[..sep_pos])
            && let Ok(next) = match_level(ctx, rule_idx, argv, pos + 1, state.clone(), failures)
        {
            return Ok(next);
        }

        if let Some(next) = try_arg_patterns(ctx, rule_idx, argv, pos, &state, failures) {
            return Ok(next);
        }

        record_failure(failures, rule_idx, &ctx.path, pos, token, fail_reason(ctx));
        return Err(());
    }

    // Non-flag token, subcommand descent first
    if let Some(sub) = ctx.subcommands.iter().find(|s| s.name == *token) {
        let sub_ctx = LevelCtx::for_sub(ctx, sub);
        let mut next = state;
        next.consumed_arg_or_sub = true;
        next.path.clone_from(&sub_ctx.path);
        return match_level(&sub_ctx, rule_idx, argv, pos + 1, next, failures);
    }

    // Positional arg pattern, rules can declare args alongside subcommands, so a non-subcommand token can still be an arg
    if let Some(next) = try_arg_patterns(ctx, rule_idx, argv, pos, &state, failures) {
        return Ok(next);
    }

    if !ctx.subcommands.is_empty() && ctx.is_top_level {
        record_failure(
            failures,
            rule_idx,
            &ctx.path,
            pos,
            token,
            "unknown subcommand",
        );
    } else {
        record_failure(failures, rule_idx, &ctx.path, pos, token, fail_reason(ctx));
    }
    Err(())
}

/// Try each arg pattern at `pos`.
/// On a fit, validate/capture and recurse.
/// Returns the deepest successful state, or None when no pattern leads to a full match.
fn try_arg_patterns(
    ctx: &LevelCtx,
    rule_idx: usize,
    argv: &[String],
    pos: usize,
    state: &MatchState,
    failures: &mut Vec<MatchFailure>,
) -> Option<MatchState> {
    let token = &argv[pos];

    for pattern in &ctx.patterns {
        match pattern {
            ArgPattern::Literal(lit) => {
                if token == lit {
                    let mut next = state.clone();
                    next.consumed_arg_or_sub = true;
                    if let Ok(done) = match_level(ctx, rule_idx, argv, pos + 1, next, failures) {
                        return Some(done);
                    }
                }
            }
            ArgPattern::InlineFlag { flag, template } => {
                let prefix = format!("{flag}{}", sep_for(ctx.style));
                if let Some(value) = token.strip_prefix(prefix.as_str()) {
                    let mut next = state.clone();
                    next.consumed_arg_or_sub = true;
                    let cap_name = capture_name(template, &mut next.arg_counter);
                    if let Err(reason) =
                        validate_template_value(value, template, &ctx.config.contracts)
                    {
                        record_failure(failures, rule_idx, &ctx.path, pos, token, &reason);
                        next.had_validation_error = true;
                    }
                    next.captures.insert(cap_name, value.to_string());
                    if let Ok(done) = match_level(ctx, rule_idx, argv, pos + 1, next, failures) {
                        return Some(done);
                    }
                }
            }
            ArgPattern::Template(template) => {
                if !is_flag_like(token, ctx.style) {
                    let mut next = state.clone();
                    next.consumed_arg_or_sub = true;
                    let cap_name = capture_name(template, &mut next.arg_counter);
                    if let Err(reason) =
                        validate_template_value(token, template, &ctx.config.contracts)
                    {
                        record_failure(failures, rule_idx, &ctx.path, pos, token, &reason);
                        next.had_validation_error = true;
                    }
                    next.captures.insert(cap_name, token.clone());
                    if let Ok(done) = match_level(ctx, rule_idx, argv, pos + 1, next, failures) {
                        return Some(done);
                    }
                }
            }
            ArgPattern::TemplateContext {
                prefix,
                suffix,
                template,
            } => {
                let works = prefix
                    .as_ref()
                    .is_none_or(|p| token.starts_with(p.as_str()))
                    && suffix.as_ref().is_none_or(|s| token.ends_with(s.as_str()));
                if works {
                    let base_start = prefix.as_ref().map_or(0, String::len);
                    let base_end = token.len() - suffix.as_ref().map_or(0, String::len);
                    if base_start < base_end {
                        let base = &token[base_start..base_end];
                        let mut next = state.clone();
                        next.consumed_arg_or_sub = true;
                        let cap_name = capture_name(template, &mut next.arg_counter);
                        if let Err(reason) =
                            validate_template_value(base, template, &ctx.config.contracts)
                        {
                            record_failure(failures, rule_idx, &ctx.path, pos, token, &reason);
                            next.had_validation_error = true;
                        }
                        next.captures.insert(cap_name, base.to_string());
                        if let Ok(done) = match_level(ctx, rule_idx, argv, pos + 1, next, failures)
                        {
                            return Some(done);
                        }
                    }
                }
            }
        }
    }

    None
}

pub(crate) fn capture_name(template: &TemplateType, counter: &mut usize) -> String {
    match template {
        TemplateType::Named { name, .. } | TemplateType::ContractRef(name) => name.clone(),
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
    use crate::errors::{GuardError, MatchFailure};
    use std::collections::HashMap;

    fn no_match_failures(err: GuardError) -> Vec<MatchFailure> {
        assert!(
            matches!(&err, GuardError::NoMatch { .. }),
            "expected NoMatch, got {err:?}"
        );
        if let GuardError::NoMatch { failures, .. } = err {
            failures
        } else {
            Vec::new()
        }
    }

    #[allow(clippy::too_many_lines)]
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
                // Rule 0 - git
                Rule {
                    action: Action::Run {
                        binary: "/opt/test/bin/git".into(),
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
                // Rule 1 - help
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

    #[test]
    fn test_match_help() {
        let cfg = make_config();
        let argv = vec!["help".to_string()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 1);
        assert_eq!(result.subcommand_path, Vec::<String>::new());
    }

    #[test]
    fn test_match_named_capture() {
        let mut cfg = make_config();
        cfg.rules[1] = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/cat".into(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("cat".into()),
            args: vec!["{path:string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        };

        let argv = vec!["cat".into(), "/etc/hostname".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("path").unwrap(), "/etc/hostname");
        assert!(!result.captures.contains_key("arg_0"));
    }

    #[test]
    fn test_match_named_capture_validates_inner_template() {
        let mut cfg = make_config();
        cfg.rules[1] = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/tail".into(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("tail".into()),
            args: vec!["-n".into(), "{n:int}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            subcommands: vec![],
        };

        let ok = match_command(&cfg, &["tail".into(), "-n".into(), "20".into()]);
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().captures.get("n").unwrap(), "20");

        let bad = match_command(&cfg, &["tail".into(), "-n".into(), "abc".into()]);
        assert!(bad.is_err(), "expected 'abc' to fail int validation");
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

    #[test]
    fn test_flags_scoped_not_recursive() {
        let cfg = make_config();
        let argv = vec!["git".into(), "status".into(), "--oneline".into()];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(!failures.is_empty());
        assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
    }

    #[test]
    fn test_top_level_flags() {
        let cfg = make_config();
        let argv = vec!["git".into(), "-C".into(), "/tmp".into(), "status".into()];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.rule_index, 0);
        assert_eq!(result.subcommand_path, vec!["status"]);
    }

    #[test]
    fn test_unknown_subcommand() {
        let cfg = make_config();
        let argv = vec!["bogus".to_string()];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason.contains("expected")));
    }

    #[test]
    fn test_rich_errors_multiple_failures() {
        let cfg = make_config();
        let argv = vec![
            "git".into(),
            "status".into(),
            "--unknown".into(),
            "extra".into(),
        ];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(!failures.is_empty());
        assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
    }

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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason.contains("not in range")));
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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason.contains("not in")));
    }

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
        let argv = ["git", "status", "--sshd"];
        let result = match_command(
            &cfg,
            &argv
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
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
        let argv = ["git", "status", "--unit.sshd.timer"];
        let result = match_command(
            &cfg,
            &argv
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
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
        let argv: Vec<String> = ["git", "status", "--bad"]
            .iter()
            .map(std::string::ToString::to_string)
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
        let argv: Vec<String> = ["git", "status", "sshd"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let result = match_command(&cfg, &argv);
        assert!(result.is_err());
    }

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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(
            failures.len() >= 2,
            "expected at least 2 failures, got {failures:?}"
        );
    }

    #[test]
    fn test_match_command_empty_argv() {
        let cfg = make_config();
        let argv: Vec<String> = vec![];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(!failures.is_empty());
        assert!(failures.iter().any(|f| f.reason == "empty command"));
    }

    #[test]
    fn test_rule_no_command() {
        let mut cfg = make_config();
        // command_name()=None -> command-name check skipped
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

    #[test]
    fn test_no_args_after_command_with_subcommands() {
        let cfg = make_config();
        let argv = vec!["git".into()];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(
            failures
                .iter()
                .any(|f| f.reason == "no arguments after command")
        );
    }

    #[test]
    fn test_unexpected_arguments_no_subcommands_no_args() {
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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason.contains("unexpected")));
    }

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
        // /verbose:true consumed at top-level by consume_flags
        let argv = vec![
            "dos-tool".into(),
            "/verbose:true".into(),
            "run".into(),
            "data".into(),
        ];
        let result = match_command(&cfg, &argv).unwrap();
        assert_eq!(result.captures.get("arg_0").unwrap(), "data");
    }

    #[test]
    fn test_walk_subcommands_token_not_found() {
        let cfg = make_config();
        // "git bogus" - "bogus" is not a subcommand of git
        let argv = vec!["git".into(), "bogus".into()];
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason == "unknown subcommand"));
    }

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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
    }

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
        let failures = no_match_failures(match_command(&cfg, &argv).unwrap_err());
        assert!(failures.iter().any(|f| f.reason == "not in allowed args"));
    }

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
    // ---- Trailing / interleaved flag orders (transparent CLI semantics) ----

    #[test]
    fn test_flag_after_positional_arg() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into(), "-i".into()],
            subcommands: vec![],
        });
        let result = match_command(&cfg, &["df".into(), "/var".into(), "-h".into()]);
        assert!(result.is_ok(), "expected 'df /var -h' to match");
    }

    #[test]
    fn test_flag_then_positional_arg() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into(), "-i".into()],
            subcommands: vec![],
        });
        let result = match_command(&cfg, &["df".into(), "-h".into(), "/var".into()]);
        assert!(result.is_ok(), "expected 'df -h /var' to match");
    }

    #[test]
    fn test_interleaved_flags_and_args() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into(), "{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into(), "-i".into()],
            subcommands: vec![],
        });
        let result = match_command(
            &cfg,
            &[
                "df".into(),
                "/".into(),
                "-h".into(),
                "/var".into(),
                "-i".into(),
            ],
        );
        assert!(result.is_ok(), "expected interleaved flags/args to match");
    }

    #[test]
    fn test_subcommand_flag_after_positional_args() {
        let cfg = make_config();
        let result = match_command(
            &cfg,
            &[
                "git".into(),
                "status".into(),
                "myfile".into(),
                "--porcelain".into(),
            ],
        );
        assert!(
            result.is_ok(),
            "expected 'git status myfile --porcelain' to match"
        );
    }

    #[test]
    fn test_disallowed_flag_after_positional_still_denied() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into()],
            subcommands: vec![],
        });
        let result = match_command(&cfg, &["df".into(), "/var".into(), "--follow".into()]);
        assert!(
            result.is_err(),
            "expected disallowed trailing flag to be denied"
        );
    }

    #[test]
    fn test_disallowed_flag_between_args_still_denied() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into(), "{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into()],
            subcommands: vec![],
        });
        let result = match_command(
            &cfg,
            &["df".into(), "/".into(), "--follow".into(), "/var".into()],
        );
        assert!(
            result.is_err(),
            "expected disallowed interleaved flag to be denied"
        );
    }

    #[test]
    fn test_value_taking_flag_then_flag_then_arg() {
        // -n 3 --no-pager <path>: value flag, standalone flag, then positional
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("tail".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-n".into(), "--no-pager".into()],
            subcommands: vec![],
        });
        let result = match_command(
            &cfg,
            &[
                "tail".into(),
                "-n".into(),
                "3".into(),
                "--no-pager".into(),
                "/var/log/x".into(),
            ],
        );
        assert!(
            result.is_ok(),
            "expected 'tail -n 3 --no-pager <path>' to match"
        );
    }

    #[test]
    fn test_repeated_flags_anywhere() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["-h".into(), "-i".into()],
            subcommands: vec![],
        });
        let result = match_command(&cfg, &["df".into(), "-h".into(), "/".into(), "-h".into()]);
        assert!(
            result.is_ok(),
            "repeated flags should be accepted in any position"
        );
    }

    #[test]
    fn test_flag_eq_value_after_positional() {
        let mut cfg = make_config();
        cfg.rules.push(Rule {
            action: Action::ShowHelp,
            command: Some("df".into()),
            args: vec!["{string}".into()],
            pre_args: vec![],
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec!["--output".into()],
            subcommands: vec![],
        });
        let result = match_command(&cfg, &["df".into(), "/var".into(), "--output=json".into()]);
        assert!(result.is_ok(), "flag=value after positional should match");
    }
}
