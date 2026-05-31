use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use crate::config::action::Action;
use crate::config::duration::Duration;
use crate::config::rule::Rule;
use crate::config::subcommand::Subcommand;
use crate::config::Config;
use crate::errors::GuardError;

fn resolve_within_roots(input_path: &Path, root_set: &[String]) -> Result<(), GuardError> {
    let resolved = input_path.canonicalize().map_err(|_| {
        GuardError::PathNotAllowed(format!("cannot resolve path '{}'", input_path.display()))
    })?;

    for root_str in root_set {
        let root_path = Path::new(root_str);
        if resolved.starts_with(root_path) {
            return Ok(());
        }
    }

    Err(GuardError::PathNotAllowed(format!(
        "path '{}' not within any allowed root",
        resolved.display()
    )))
}

fn resolve_path_parent(input_path: &Path, root_set: &[String]) -> Result<(), GuardError> {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    resolve_within_roots(parent, root_set)
}

fn resolve_binary(binary: &str, implicit_symlinks: bool) -> Result<String, GuardError> {
    let path = Path::new(binary);
    if !path.exists() {
        return Err(GuardError::Action(format!(
            "binary '{binary}' does not exist"
        )));
    }
    if implicit_symlinks {
        match path.canonicalize() {
            Ok(resolved) => Ok(resolved.display().to_string()),
            Err(e) => Err(GuardError::Action(format!(
                "cannot resolve binary '{binary}': {e}"
            ))),
        }
    } else {
        let meta = std::fs::symlink_metadata(binary)?;
        if meta.file_type().is_symlink() {
            return Err(GuardError::Action(format!(
                "binary '{binary}' is a symlink and implicit_symlinks is disabled"
            )));
        }
        Ok(binary.to_string())
    }
}

fn find_sub_by_name<'a>(subs: &'a [Subcommand], name: &str) -> Option<&'a Subcommand> {
    subs.iter().find(|s| s.name == name)
}

/// Build the final argv for a `Run` action.
///
/// Subcommand names are auto-injected from `sub.name`, followed by `pre_args`.
/// Only `action.args`, auto-injected subcommand names, `pre_args`, and
/// user-supplied flags/positionals appear in the final argv.
fn build_command_argv(
    rule: &Rule,
    subcommand_path: &[String],
    user_argv: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();

    // 1. Static pre-args from the action
    if let Action::Run { args, .. } = &rule.action {
        argv.extend(args.clone());
    }

    // 2. Skip command routing token (first token that matched rule.command_name())
    let cmd_name = rule.command_name();
    let mut i: usize = 0;
    if let Some(cmd) = cmd_name {
        if i < user_argv.len() && user_argv[i] == cmd {
            i += 1;
        }
    }

    // 3. Walk user_argv token-by-token; inject pre_args when token matches
    //    next expected subcommand name.
    let mut sub_level: usize = 0;
    let mut subs: &[Subcommand] = &rule.subcommands;

    while i < user_argv.len() && sub_level < subcommand_path.len() {
        let token = &user_argv[i];
        i += 1;

        if token == &subcommand_path[sub_level] {
            // Routing token — auto-inject sub.name + pre_args
            if let Some(sub) = find_sub_by_name(subs, &subcommand_path[sub_level]) {
                argv.push(sub.name.clone());
                argv.extend(sub.pre_args.clone());
                subs = &sub.subcommands;
            }
            sub_level += 1;
        } else {
            // Regular token (flag, positional arg) — pass through
            argv.push(token.clone());
        }
    }

    // 3. Append remaining user argv after last subcommand
    if i < user_argv.len() {
        argv.extend_from_slice(&user_argv[i..]);
    }

    argv
}

fn action_run(
    binary: &str,
    argv: &[String],
    implicit_symlinks: bool,
    timeout: &Duration,
) -> Result<i32, GuardError> {
    let resolved = resolve_binary(binary, implicit_symlinks)?;

    let mut child = std::process::Command::new(&resolved)
        .args(argv)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| GuardError::Action(format!("cannot spawn '{resolved}': {e}")))?;

    let start = Instant::now();
    let timeout_dur = std::time::Duration::from_millis(timeout.millis);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(1)),
            Ok(None) => {
                if start.elapsed() > timeout_dur {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(GuardError::Action(format!(
                        "command '{binary}' timed out after {}ms",
                        timeout.millis
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(GuardError::Action(format!(
                    "error waiting for '{binary}': {e}"
                )));
            }
        }
    }
}

fn action_read_file(path_str: &str, config: &Config) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, &config.roots)?;

    let meta = std::fs::metadata(path)?;
    if meta.len() > config.global.max_read_bytes as u64 {
        return Err(GuardError::Action(format!(
            "file '{}' is {} bytes, exceeds limit of {}",
            path.display(),
            meta.len(),
            config.global.max_read_bytes
        )));
    }

    let contents = std::fs::read_to_string(path)?;
    print!("{contents}");
    Ok(())
}

fn action_tail_file(path_str: &str, lines: usize, config: &Config) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, &config.roots)?;

    let lines = lines.min(config.global.max_tail_lines);

    let output = std::process::Command::new("tail")
        .arg("-n")
        .arg(lines.to_string())
        .arg(path_str)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| GuardError::Action(format!("cannot run tail: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GuardError::Action(format!("tail failed: {stderr}")));
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn action_stat_path(path_str: &str, config: &Config) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_path_parent(path, &config.roots)?;

    let meta = std::fs::symlink_metadata(path)?;
    let file_type = meta.file_type();
    let type_str = if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "file"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "other"
    };

    println!("path: {}", path.display());
    println!("type: {type_str}");
    println!("size: {}", meta.len());
    Ok(())
}

fn action_list_dir(path_str: &str, config: &Config) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, &config.roots)?;

    let mut entries: Vec<_> = std::fs::read_dir(path)
        .map_err(|e| {
            GuardError::Action(format!("cannot read directory '{}': {e}", path.display()))
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();

    entries.sort();
    for entry in entries {
        println!("{}", entry.to_string_lossy());
    }
    Ok(())
}

fn execute_run(
    _config: &Config,
    rule: &Rule,
    subcommand_path: &[String],
    user_argv: &[String],
) -> Result<i32, GuardError> {
    if let Action::Run {
        binary, timeout, ..
    } = &rule.action
    {
        let argv = build_command_argv(rule, subcommand_path, user_argv);
        action_run(binary, &argv, rule.implicit_symlinks, timeout)
    } else {
        Err(GuardError::Action("expected Run action".into()))
    }
}

fn execute_read_file(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String>,
) -> Result<i32, GuardError> {
    if let Action::ReadFile {
        path_capture,
        root_set,
    } = action
    {
        let path = captures
            .get(path_capture.as_str())
            .ok_or_else(|| GuardError::Action(format!("missing capture '{path_capture}'")))?;
        if root_set != "roots" {
            return Err(GuardError::Action(format!("unknown root set '{root_set}'")));
        }
        action_read_file(path, config)?;
        Ok(0)
    } else {
        Err(GuardError::Action("expected ReadFile action".into()))
    }
}

fn execute_tail_file(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String>,
) -> Result<i32, GuardError> {
    if let Action::TailFile {
        path_capture,
        lines_capture,
        default_lines,
        root_set,
    } = action
    {
        let path = captures
            .get(path_capture.as_str())
            .ok_or_else(|| GuardError::Action(format!("missing capture '{path_capture}'")))?;
        let lines = lines_capture
            .as_ref()
            .and_then(|lc| captures.get(lc.as_str()))
            .and_then(|l| l.parse::<usize>().ok())
            .unwrap_or(*default_lines);
        if root_set != "roots" {
            return Err(GuardError::Action(format!("unknown root set '{root_set}'")));
        }
        action_tail_file(path, lines, config)?;
        Ok(0)
    } else {
        Err(GuardError::Action("expected TailFile action".into()))
    }
}

fn execute_stat_path(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String>,
) -> Result<i32, GuardError> {
    if let Action::StatPath {
        path_capture,
        root_set,
    } = action
    {
        let path = captures
            .get(path_capture.as_str())
            .ok_or_else(|| GuardError::Action(format!("missing capture '{path_capture}'")))?;
        if root_set != "roots" {
            return Err(GuardError::Action(format!("unknown root set '{root_set}'")));
        }
        action_stat_path(path, config)?;
        Ok(0)
    } else {
        Err(GuardError::Action("expected StatPath action".into()))
    }
}

fn execute_list_dir(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String>,
) -> Result<i32, GuardError> {
    if let Action::ListDir {
        path_capture,
        root_set,
    } = action
    {
        let path = captures
            .get(path_capture.as_str())
            .ok_or_else(|| GuardError::Action(format!("missing capture '{path_capture}'")))?;
        if root_set != "roots" {
            return Err(GuardError::Action(format!("unknown root set '{root_set}'")));
        }
        action_list_dir(path, config)?;
        Ok(0)
    } else {
        Err(GuardError::Action("expected ListDir action".into()))
    }
}

fn execute_show_help(config: &Config) -> Result<i32, GuardError> {
    print!("{}", config.global.help_text);
    Ok(0)
}

pub fn execute(
    config: &Config,
    rule: &Rule,
    subcommand_path: &[String],
    captures: &HashMap<String, String>,
    user_argv: &[String],
) -> Result<i32, GuardError> {
    let action_tag = match &rule.action {
        Action::Run { .. } => 0u8,
        Action::ReadFile { .. } => 1,
        Action::TailFile { .. } => 2,
        Action::StatPath { .. } => 3,
        Action::ListDir { .. } => 4,
        Action::ShowHelp => 5,
    };

    match action_tag {
        0 => execute_run(config, rule, subcommand_path, user_argv),
        1 => execute_read_file(config, &rule.action, captures),
        2 => execute_tail_file(config, &rule.action, captures),
        3 => execute_stat_path(config, &rule.action, captures),
        4 => execute_list_dir(config, &rule.action, captures),
        5 => execute_show_help(config),
        _ => Err(GuardError::Action("unknown action type".into())),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::arg::ArgStyle;

    use super::*;

    fn make_systemctl_rule() -> Rule {
        Rule {
            action: Action::Run {
                binary: "/run/current-system/sw/bin/systemctl".into(),
                args: vec!["--no-pager".into()],
                timeout: Duration { millis: 5000 },
            },
            command: Some("systemctl".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![
                Subcommand {
                    name: "status".into(),
                    arg_style: None,
                    flag_groups: vec![],
                    flags: vec![],
                    args: vec![],
                    pre_args: vec!["--no-pager".into(), "--full".into()],
                    subcommands: vec![],
                },
                Subcommand {
                    name: "show".into(),
                    arg_style: None,
                    flag_groups: vec![],
                    flags: vec![],
                    args: vec![],
                    pre_args: vec!["--property=Id,Type,ActiveState".into()],
                    subcommands: vec![],
                },
            ],
        }
    }

    fn make_simple_rule() -> Rule {
        Rule {
            action: Action::Run {
                binary: "/bin/journalctl".into(),
                args: vec!["--no-pager".into()],
                timeout: Duration { millis: 5000 },
            },
            command: Some("journalctl".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        }
    }

    #[test]
    fn test_build_command_systemctl_status() {
        let rule = make_systemctl_rule();
        // User types: systemctl status angrr
        let user_argv = vec![
            "systemctl".to_string(),
            "status".to_string(),
            "angrr".to_string(),
        ];
        let subcommand_path = vec!["status".to_string()];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        // Should produce: systemctl --no-pager status --no-pager --full angrr
        assert_eq!(
            result,
            vec![
                "--no-pager".to_string(),
                "status".to_string(),
                "--no-pager".to_string(),
                "--full".to_string(),
                "angrr".to_string()
            ]
        );
    }

    #[test]
    fn test_build_command_systemctl_show() {
        let rule = make_systemctl_rule();
        let user_argv = vec![
            "systemctl".to_string(),
            "show".to_string(),
            "sshd".to_string(),
        ];
        let subcommand_path = vec!["show".to_string()];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        assert_eq!(
            result,
            vec![
                "--no-pager".to_string(),
                "show".to_string(),
                "--property=Id,Type,ActiveState".to_string(),
                "sshd".to_string()
            ]
        );
    }

    #[test]
    fn test_build_command_no_subcommand() {
        let rule = make_simple_rule();
        // User types: journalctl -u sshd -n 10
        let user_argv = vec![
            "journalctl".to_string(),
            "-u".to_string(),
            "sshd".to_string(),
            "-n".to_string(),
            "10".to_string(),
        ];
        let subcommand_path: Vec<String> = vec![];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        // Command token skipped, everything else passed through
        assert_eq!(
            result,
            vec![
                "--no-pager".to_string(),
                "-u".to_string(),
                "sshd".to_string(),
                "-n".to_string(),
                "10".to_string()
            ]
        );
    }

    #[test]
    fn test_build_command_no_args() {
        let rule = make_simple_rule();
        let user_argv = vec!["journalctl".to_string()];
        let subcommand_path: Vec<String> = vec![];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        assert_eq!(result, vec!["--no-pager".to_string()]);
    }

    #[test]
    fn test_build_command_nested_subcommands() {
        let rule = Rule {
            action: Action::Run {
                binary: "/bin/git".into(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("git".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![Subcommand {
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
                    args: vec![],
                    pre_args: vec!["--verbose".into()],
                    subcommands: vec![],
                }],
            }],
        };

        // User types: git remote add origin
        let user_argv = vec![
            "git".to_string(),
            "remote".to_string(),
            "add".to_string(),
            "origin".to_string(),
        ];
        let subcommand_path = vec!["remote".to_string(), "add".to_string()];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        assert_eq!(
            result,
            vec![
                "remote".to_string(),
                "add".to_string(),
                "--verbose".to_string(),
                "origin".to_string()
            ]
        );
    }

    #[test]
    fn test_build_command_command_not_first() {
        // Edge case: command token not at position 0 (shouldn't happen in practice)
        let rule = make_systemctl_rule();
        let user_argv = vec![
            "other".to_string(),
            "systemctl".to_string(),
            "status".to_string(),
            "angrr".to_string(),
        ];
        let subcommand_path = vec!["status".to_string()];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        // Command token not skipped (argv[0] != "systemctl"), passes through as regular token
        // "status" matches routing → inject "status" + pre_args
        assert_eq!(
            result,
            vec![
                "--no-pager".to_string(),
                "other".to_string(),
                "systemctl".to_string(),
                "status".to_string(),
                "--no-pager".to_string(),
                "--full".to_string(),
                "angrr".to_string()
            ]
        );
    }

    #[test]
    fn test_build_command_only_command_no_subcommand() {
        let rule = make_simple_rule();
        let user_argv = vec!["journalctl".to_string()];
        let subcommand_path: Vec<String> = vec![];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        assert_eq!(result, vec!["--no-pager".to_string()]);
    }

    #[test]
    fn test_build_command_action_args_before_subcommand() {
        // Action-level args are prepended before subcommand name + pre_args
        let rule = Rule {
            action: Action::Run {
                binary: "/bin/cmd".to_string(),
                args: vec!["--binary-flag".to_string()],
                timeout: Duration { millis: 5000 },
            },
            command: Some("cmd".to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![Subcommand {
                name: "sub".to_string(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec!["--sub-flag".to_string()],
                subcommands: vec![],
            }],
        };
        let user_argv = vec!["cmd".to_string(), "sub".to_string(), "arg1".to_string()];
        let sub_path = vec!["sub".to_string()];
        let result = build_command_argv(&rule, &sub_path, &user_argv);
        assert_eq!(
            result,
            vec![
                "--binary-flag".to_string(),
                "sub".to_string(),
                "--sub-flag".to_string(),
                "arg1".to_string(),
            ]
        );
    }

    #[test]
    fn test_build_command_deeply_nested_three_levels() {
        // All subcommand pre_args collected across nesting levels
        let rule = Rule {
            action: Action::Run {
                binary: "/bin/git".to_string(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("git".to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![Subcommand {
                name: "remote".to_string(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec!["--l1".to_string()],
                subcommands: vec![Subcommand {
                    name: "add".to_string(),
                    arg_style: None,
                    flag_groups: vec![],
                    flags: vec![],
                    args: vec![],
                    pre_args: vec!["--l2".to_string()],
                    subcommands: vec![Subcommand {
                        name: "verbose".to_string(),
                        arg_style: None,
                        flag_groups: vec![],
                        flags: vec![],
                        args: vec![],
                        pre_args: vec!["--l3".to_string()],
                        subcommands: vec![],
                    }],
                }],
            }],
        };
        let user_argv = vec![
            "git".to_string(),
            "remote".to_string(),
            "add".to_string(),
            "verbose".to_string(),
            "origin".to_string(),
        ];
        let sub_path = vec![
            "remote".to_string(),
            "add".to_string(),
            "verbose".to_string(),
        ];
        let result = build_command_argv(&rule, &sub_path, &user_argv);
        assert_eq!(
            result,
            vec![
                "remote".to_string(),
                "--l1".to_string(),
                "add".to_string(),
                "--l2".to_string(),
                "verbose".to_string(),
                "--l3".to_string(),
                "origin".to_string(),
            ]
        );
    }

    #[test]
    fn test_build_command_user_tokens_passthrough() {
        // Non-command, non-subcommand tokens pass through verbatim
        let rule = Rule {
            action: Action::Run {
                binary: "/bin/cmd".to_string(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("cmd".to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![Subcommand {
                name: "sub".to_string(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec!["--sub-flag".to_string()],
                subcommands: vec![],
            }],
        };
        let user_argv = vec![
            "cmd".to_string(),
            "--flag".to_string(),
            "value".to_string(),
            "sub".to_string(),
            "extra".to_string(),
        ];
        let sub_path = vec!["sub".to_string()];
        let result = build_command_argv(&rule, &sub_path, &user_argv);
        assert_eq!(
            result,
            vec![
                "--flag".to_string(),
                "value".to_string(),
                "sub".to_string(),
                "--sub-flag".to_string(),
                "extra".to_string(),
            ]
        );
    }

    #[test]
    fn test_build_command_multiple_tokens_before_subcommand() {
        // User flags/positionals before subcommand match pass through
        let rule = make_systemctl_rule();
        let user_argv = vec![
            "systemctl".into(),
            "-H".into(),
            "host.example.com".into(),
            "status".into(),
            "sshd".into(),
        ];
        let sub_path = vec!["status".into()];
        let result = build_command_argv(&rule, &sub_path, &user_argv);
        assert_eq!(
            result,
            vec![
                "--no-pager".to_string(),
                "-H".to_string(),
                "host.example.com".to_string(),
                "status".to_string(),
                "--no-pager".to_string(),
                "--full".to_string(),
                "sshd".to_string(),
            ]
        );
    }

    #[test]
    fn test_build_command_no_action_args_with_subcommand() {
        // Empty action args, only subcommand name + pre_args injected
        let rule = Rule {
            action: Action::Run {
                binary: "/bin/cmd".to_string(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("cmd".to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![Subcommand {
                name: "sub".to_string(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec!["--internal".to_string()],
                subcommands: vec![],
            }],
        };
        let user_argv = vec!["cmd".to_string(), "sub".to_string()];
        let sub_path = vec!["sub".to_string()];
        let result = build_command_argv(&rule, &sub_path, &user_argv);
        assert_eq!(result, vec!["sub".to_string(), "--internal".to_string()]);
    }
}
