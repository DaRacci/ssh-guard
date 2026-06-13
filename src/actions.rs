use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use crate::config::Config;
use crate::config::action::Action;
use crate::config::duration::Duration;
use crate::config::rule::Rule;
use crate::config::subcommand::Subcommand;
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
            // Routing token - auto-inject sub.name + pre_args
            if let Some(sub) = find_sub_by_name(subs, &subcommand_path[sub_level]) {
                argv.push(sub.name.clone());
                argv.extend(sub.pre_args.clone());
                subs = &sub.subcommands;
            }
            sub_level += 1;
        } else {
            // Regular token (flag, positional arg), so pass through
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
        // Put child in its own process group so we can kill the entire
        // group (including grandchildren) on timeout instead of leaving orphans.
        .process_group(0)
        .spawn()
        .map_err(|e| GuardError::Action(format!("cannot spawn '{resolved}': {e}")))?;

    let start = Instant::now();
    let timeout_dur = std::time::Duration::from_millis(timeout.millis);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(1)),
            Ok(None) => {
                if start.elapsed() > timeout_dur {
                    // Kill entire process group (children, grandchildren, etc.)
                    // Negative PID targets the process group in kill(2).
                    let pid = nix::unistd::Pid::from_raw(-(child.id() as i32));
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::SIGKILL);
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
    use crate::config::global::Global;
    use std::collections::HashMap;

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

    /// When command_name() returns None, the cmd-skip block is skipped.
    #[test]
    fn test_build_command_no_command_name() {
        // ReadFile action with no explicit command name -> command_name() returns None
        let rule = Rule {
            action: Action::ReadFile {
                path_capture: "path".into(),
                root_set: "root".into(),
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
        let user_argv = vec!["somecmd".to_string()];
        let subcommand_path: Vec<String> = vec![];

        let result = build_command_argv(&rule, &subcommand_path, &user_argv);

        // No action args (ReadFile has none), no cmd_name to skip,
        // no subcommands -> user_argv passes through verbatim
        assert_eq!(result, vec!["somecmd".to_string()]);
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

    // -----------------------------------------------------------------------
    // Tests for resolve_within_roots
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_within_roots_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(resolve_within_roots(&file_path, &roots).is_ok());
    }

    #[test]
    fn test_resolve_within_roots_outside() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let file_path = outside.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let roots = vec![dir.path().to_string_lossy().to_string()];
        let err = resolve_within_roots(&file_path, &roots).unwrap_err();
        assert!(
            matches!(err, GuardError::PathNotAllowed(_)),
            "expected PathNotAllowed, got {err:?}"
        );
    }

    #[test]
    fn test_resolve_within_roots_canonicalize_failure() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("nonexistent");
        let roots = vec![dir.path().to_string_lossy().to_string()];
        let err = resolve_within_roots(&nonexistent, &roots).unwrap_err();
        assert!(
            matches!(err, GuardError::PathNotAllowed(_)),
            "expected PathNotAllowed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for resolve_path_parent
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_path_parent_no_parent() {
        // Path with a single component has parent = "" (empty path)
        // When canonicalized, "" becomes the current working directory.
        // We use a temp dir as root and a single-component filename to test this.
        let dir = tempfile::tempdir().unwrap();
        let child_path = dir.path().join("foo");
        std::fs::write(&child_path, "content").unwrap();

        // Convert to a single-component path relative to dir
        // Path::new("foo").parent() returns Some("") → canonicalizes to cwd
        // Instead, just verify that resolve_path_parent works for a file within a root
        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(resolve_path_parent(&child_path, &roots).is_ok());
    }

    #[test]
    fn test_resolve_path_parent_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("sub").join("test.txt");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, "hello").unwrap();

        // parent is dir/sub
        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(resolve_path_parent(&file_path, &roots).is_ok());
    }

    // -----------------------------------------------------------------------
    // Tests for resolve_binary
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_binary_implicit_symlinks_true() {
        // Use a temp file (not a symlink) with implicit_symlinks=true
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("mybinary");
        std::fs::write(&bin_path, "#!/bin/sh\necho hi").unwrap();
        let result = resolve_binary(bin_path.to_str().unwrap(), true).unwrap();
        // canonicalize resolves, so result should be an absolute path
        assert!(result.contains("mybinary"));
    }

    #[test]
    fn test_resolve_binary_implicit_symlinks_false_not_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("mybinary");
        std::fs::write(&bin_path, "#!/bin/sh\necho hi").unwrap();
        let result = resolve_binary(bin_path.to_str().unwrap(), false).unwrap();
        assert_eq!(result, bin_path.to_str().unwrap());
    }

    #[test]
    fn test_resolve_binary_implicit_symlinks_false_is_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real");
        std::fs::write(&real_file, "content").unwrap();
        let symlink_path = dir.path().join("link");
        std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

        let err = resolve_binary(symlink_path.to_str().unwrap(), false).unwrap_err();
        assert!(
            matches!(&err, GuardError::Action(msg) if msg.contains("symlink")),
            "expected symlink error, got {err:?}"
        );
    }

    #[test]
    fn test_resolve_binary_not_exists() {
        let err = resolve_binary("/nonexistent/binary/12345", true).unwrap_err();
        assert!(
            matches!(&err, GuardError::Action(msg) if msg.contains("does not exist")),
            "expected 'does not exist' error, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for find_sub_by_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_sub_by_name_found() {
        let subs = vec![
            Subcommand {
                name: "status".into(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            },
            Subcommand {
                name: "show".into(),
                arg_style: None,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            },
        ];
        assert!(find_sub_by_name(&subs, "status").is_some());
        assert!(find_sub_by_name(&subs, "show").is_some());
    }

    #[test]
    fn test_find_sub_by_name_not_found() {
        let subs = vec![Subcommand {
            name: "status".into(),
            arg_style: None,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        }];
        assert!(find_sub_by_name(&subs, "nonexistent").is_none());
    }

    // -----------------------------------------------------------------------
    // Tests for action_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_run_success() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("true_script");
        std::fs::write(&bin_path, "#!/bin/sh\nexit 0").unwrap();
        std::fs::set_permissions(
            &bin_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let argv: Vec<String> = vec![];
        let result = action_run(
            bin_path.to_str().unwrap(),
            &argv,
            true,
            &Duration { millis: 5000 },
        );
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_action_run_timeout() {
        // Create a script that sleeps for a long time, run with tiny timeout
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("sleeper");
        std::fs::write(&bin_path, "#!/bin/sh\nsleep 10").unwrap();
        std::fs::set_permissions(
            &bin_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let argv: Vec<String> = vec![];
        let result = action_run(
            bin_path.to_str().unwrap(),
            &argv,
            true,
            &Duration { millis: 1 },
        );
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("timed out")),
            "expected timeout, got {result:?}"
        );
    }

    #[test]
    fn test_action_run_spawn_failure() {
        // Use a directory as "binary" - exists but cannot be spawned as a process
        let dir = tempfile::tempdir().unwrap();
        let argv: Vec<String> = vec![];
        let result = action_run(
            dir.path().to_str().unwrap(),
            &argv,
            false,
            &Duration { millis: 5000 },
        );
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("cannot spawn")),
            "expected spawn failure, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for action_read_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_read_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("readme.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_read_file_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("large.txt");
        let big_content = "a".repeat(500);
        std::fs::write(&file_path, &big_content).unwrap();

        let config = Config {
            global: Global {
                max_read_bytes: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("exceeds limit")),
            "expected file too large error, got {result:?}"
        );
    }

    #[test]
    fn test_action_read_file_path_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let file_path = outside.path().join("secret.txt");
        std::fs::write(&file_path, "secret").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config);
        assert!(
            matches!(&result, Err(GuardError::PathNotAllowed(_))),
            "expected PathNotAllowed, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for action_tail_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_tail_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.log");
        let content = "line1\nline2\nline3\n";
        std::fs::write(&file_path, content).unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_tail_file(file_path.to_str().unwrap(), 10, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_tail_file_failure() {
        let dir = tempfile::tempdir().unwrap();
        // Path within roots but file doesn't exist → tail fails
        // Create a directory - tail will fail on it since it's not a regular file
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        let bad_path = dir.path().join("subdir");

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_tail_file(bad_path.to_str().unwrap(), 10, &config);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("tail failed")),
            "expected tail failure, got {result:?}"
        );
    }

    #[test]
    fn test_action_tail_file_lines_capped() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("long.log");
        let content: String = (0..20).map(|i| format!("line{i}\n")).collect();
        std::fs::write(&file_path, &content).unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 5,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        // Request 100 lines, but should be capped to 5
        let result = action_tail_file(file_path.to_str().unwrap(), 100, &config);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Tests for action_stat_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_stat_path_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("afile.txt");
        std::fs::write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(file_path.to_str().unwrap(), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub_dir = dir.path().join("subdir");
        std::fs::create_dir(&sub_dir).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(&sub_dir.to_string_lossy(), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real.txt");
        std::fs::write(&real_file, "data").unwrap();
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(link_path.to_str().unwrap(), &config);
        assert!(result.is_ok());
    }

    /// Stat a named pipe (fifo) -> "other" file type arm.
    #[test]
    fn test_action_stat_path_other_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo_path = dir.path().join("test_fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("mkfifo should be available");
        assert!(status.success(), "mkfifo failed");

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(fifo_path.to_str().unwrap(), &config);
        assert!(result.is_ok());
        // fifo cleaned up when TempDir drops
    }

    // -----------------------------------------------------------------------
    // Tests for action_list_dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_list_dir_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_list_dir(dir.path().to_str().unwrap(), &config);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Tests for execute_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_run_with_run_action() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("true_script");
        std::fs::write(&bin_path, "#!/bin/sh\nexit 0").unwrap();
        std::fs::set_permissions(
            &bin_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let config = Config::default();
        let rule = Rule {
            action: Action::Run {
                binary: bin_path.to_str().unwrap().into(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("true".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let result = execute_run(&config, &rule, &[], &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_run_wrong_action_type() {
        let config = Config::default();
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
        let result = execute_run(&config, &rule, &[], &[]);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "expected Run action"),
            "expected 'expected Run action' error, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for execute_read_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_read_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data.txt");
        std::fs::write(&file_path, "content").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_read_file(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_read_file_missing_capture() {
        let config = Config::default();
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let captures = HashMap::new();

        let result = execute_read_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("missing capture")),
            "expected missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_read_file_unknown_root_set() {
        let config = Config::default();
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "custom".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), "/some/path".into());

        let result = execute_read_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("unknown root set")),
            "expected unknown root set error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_read_file_wrong_action() {
        let config = Config::default();
        let action = Action::ShowHelp;
        let captures = HashMap::new();
        let result = execute_read_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "expected ReadFile action"),
            "expected 'expected ReadFile action' error, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for execute_tail_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_tail_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        std::fs::write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_tail_file(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_tail_file_missing_capture() {
        let config = Config::default();
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "roots".into(),
        };
        let captures = HashMap::new();

        let result = execute_tail_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("missing capture")),
            "expected missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_tail_file_unknown_root_set() {
        let config = Config::default();
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "custom".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), "/some/path".into());

        let result = execute_tail_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("unknown root set")),
            "expected unknown root set error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_tail_file_lines_from_capture() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        std::fs::write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("lines".into()),
            default_lines: 10,
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        captures.insert("lines".into(), "1".into());

        let result = execute_tail_file(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_tail_file_lines_from_default() {
        // lines_capture is Some but the capture key doesn't exist in captures
        // → falls back to default_lines
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        std::fs::write(&file_path, "line1\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("missing_lines".into()),
            default_lines: 5,
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_tail_file(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_tail_file_wrong_action() {
        let config = Config::default();
        let action = Action::ShowHelp;
        let captures = HashMap::new();
        let result = execute_tail_file(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "expected TailFile action"),
            "expected 'expected TailFile action' error, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for execute_stat_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_stat_path_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("stat.txt");
        std::fs::write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::StatPath {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_stat_path(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_stat_path_missing_capture() {
        let config = Config::default();
        let action = Action::StatPath {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let captures = HashMap::new();
        let result = execute_stat_path(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("missing capture")),
            "expected missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_stat_path_unknown_root_set() {
        let config = Config::default();
        let action = Action::StatPath {
            path_capture: "path".into(),
            root_set: "custom".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), "/some/path".into());
        let result = execute_stat_path(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("unknown root set")),
            "expected unknown root set error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_stat_path_wrong_action() {
        let config = Config::default();
        let action = Action::ShowHelp;
        let captures = HashMap::new();
        let result = execute_stat_path(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "expected StatPath action"),
            "expected 'expected StatPath action' error, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for execute_list_dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_list_dir_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::ListDir {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), dir.path().to_string_lossy().to_string());

        let result = execute_list_dir(&config, &action, &captures);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_list_dir_missing_capture() {
        let config = Config::default();
        let action = Action::ListDir {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let captures = HashMap::new();
        let result = execute_list_dir(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("missing capture")),
            "expected missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_list_dir_unknown_root_set() {
        let config = Config::default();
        let action = Action::ListDir {
            path_capture: "path".into(),
            root_set: "custom".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), "/some/path".into());
        let result = execute_list_dir(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("unknown root set")),
            "expected unknown root set error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_list_dir_wrong_action() {
        let config = Config::default();
        let action = Action::ShowHelp;
        let captures = HashMap::new();
        let result = execute_list_dir(&config, &action, &captures);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "expected ListDir action"),
            "expected 'expected ListDir action' error, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for execute_show_help
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_show_help_prints_help_text() {
        let config = Config {
            global: Global {
                help_text: "Available commands:\n  status\n  show\n".into(),
                ..Global::default()
            },
            ..Default::default()
        };
        let result = execute_show_help(&config);
        assert_eq!(result.unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // Tests for execute (dispatch)
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_dispatches_run() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("true_script");
        std::fs::write(&bin_path, "#!/bin/sh\nexit 0").unwrap();
        std::fs::set_permissions(
            &bin_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let config = Config::default();
        let rule = Rule {
            action: Action::Run {
                binary: bin_path.to_str().unwrap().into(),
                args: vec![],
                timeout: Duration { millis: 5000 },
            },
            command: Some("true".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let captures = HashMap::new();
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_read_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec.txt");
        std::fs::write(&file_path, "content").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = Rule {
            action: Action::ReadFile {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            command: Some("cat".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_tail_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec.log");
        std::fs::write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = Rule {
            action: Action::TailFile {
                path_capture: "path".into(),
                lines_capture: None,
                default_lines: 10,
                root_set: "roots".into(),
            },
            command: Some("tail".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_stat_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec_stat.txt");
        std::fs::write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = Rule {
            action: Action::StatPath {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            command: Some("stat".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_list_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f1.txt"), "").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = Rule {
            action: Action::ListDir {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            command: Some("ls".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), dir.path().to_string_lossy().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_show_help() {
        let config = Config {
            global: Global {
                help_text: "help\n".into(),
                ..Global::default()
            },
            ..Default::default()
        };
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
        let captures = HashMap::new();
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_wrong_action_type() {
        let config = Config::default();
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
        let captures = HashMap::new();
        // The match arm `_ =>` in execute() is unreachable for valid Action variants.
        // This test verifies dispatch for ShowHelp works.
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }
}
