use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use crate::config::action::Action;
use crate::config::duration::Duration;
use crate::config::rule::Rule;
use crate::config::subcommand::Subcommand;
use crate::errors::GuardError;
use crate::kinds::{EnvCtx, ExecCtx, RuleKind};

pub(super) struct Run<'a> {
    pub(super) binary: &'a str,
    pub(super) args: &'a [String],
    pub(super) timeout: &'a Duration,
}

impl RuleKind for Run<'_> {
    fn name(&self) -> &'static str {
        "run"
    }

    fn validate_env(&self, ctx: &EnvCtx<'_>, errors: &mut Vec<String>) {
        let path = Path::new(self.binary);
        if !path.is_absolute() {
            return;
        }

        if !path.exists() {
            errors.push(format!(
                "{} rule[{}]: binary '{}' does not exist",
                ctx.scope, ctx.index, self.binary
            ));
            return;
        }

        if !ctx.rule.implicit_symlinks {
            return;
        }

        match std::fs::symlink_metadata(self.binary) {
            Ok(meta) if meta.file_type().is_symlink() => match path.canonicalize() {
                Ok(resolved) => {
                    errors.push(format!(
                            "{} rule[{}]: binary '{}' is a symlink -> '{}'. Set implicit_symlinks=true or use the real path.",
                            ctx.scope,
                            ctx.index,
                            self.binary,
                            resolved.display()
                        ));
                }
                Err(_) => {
                    errors.push(format!(
                            "{} rule[{}]: binary '{}' is a symlink and cannot be resolved",
                            ctx.scope, ctx.index, self.binary
                        ));
                }
            },
            Err(error) => {
                errors.push(format!(
                    "{} rule[{}]: cannot stat binary '{}': {}",
                    ctx.scope, ctx.index, self.binary, error
                ));
            }
            _ => {}
        }
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        let _ = self.args;
        let argv = build_argv(ctx.rule, ctx.subcommand_path, ctx.user_argv, ctx.captures)?;
        action_run(self.binary, &argv, ctx.rule.implicit_symlinks, self.timeout)
    }
}

fn resolve_binary(binary: &str, implicit_symlinks: bool) -> Result<String, GuardError> {
    let path = Path::new(binary);
    if !path.exists() {
        return Err(GuardError::Action(format!(
            "binary '{binary}' does not exist"
        )));
    }

    if implicit_symlinks {
        return match path.canonicalize() {
            Ok(resolved) => Ok(resolved.display().to_string()),
            Err(e) => Err(GuardError::Action(format!(
                "cannot resolve binary '{binary}': {e}"
            ))),
        };
    }

    let meta = std::fs::symlink_metadata(binary)?;
    if meta.file_type().is_symlink() {
        return Err(GuardError::Action(format!(
            "binary '{binary}' is a symlink and implicit_symlinks is disabled"
        )));
    }
    Ok(binary.to_string())
}

fn find_sub_by_name<'a>(subs: &'a [Subcommand], name: &str) -> Option<&'a Subcommand> {
    subs.iter().find(|s| s.name == name)
}

/// Substitute `{name}` and `{name:-default}` placeholders in a config-sourced argument with values from the match captures.
///
/// Fail-closed: a placeholder with no matching capture and no default is an error.
/// `\{` and `\}` escape a literal brace; `\\` escapes a backslash.
fn substitute_arg_template(
    arg: &str,
    captures: &HashMap<String, String>,
) -> Result<String, GuardError> {
    let mut out = String::with_capacity(arg.len());
    let mut chars = arg.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some(&e @ ('{' | '}' | '\\')) => {
                    out.push(e);
                    chars.next();
                }
                _ => out.push(c),
            }
        } else if c == '{' {
            let mut inner = String::new();
            let mut closed = false;
            for ic in chars.by_ref() {
                if ic == '}' {
                    closed = true;
                    break;
                }
                inner.push(ic);
            }
            if !closed {
                out.push('{');
                out.push_str(&inner);
                continue;
            }
            let (name, default) = match inner.split_once(":-") {
                Some((n, d)) => (n, Some(d)),
                None => (inner.as_str(), None),
            };
            if let Some(value) = captures.get(name) {
                out.push_str(value);
            } else if let Some(value) = default {
                out.push_str(value);
            } else {
                return Err(GuardError::Action(format!(
                    "missing capture '{name}' for template '{arg}'"
                )));
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Build final argv for `Run` action.
///
/// Subcommand names are auto-injected from `sub.name`, followed by `pre_args`.
/// `{name}` placeholders in `action.args` and all `pre_args` are resolved from match captures,
/// with `{name:-default}` fallbacks.
///
/// Only config-sourced strings and user-supplied flags/positionals appear in final argv.
pub(crate) fn build_argv(
    rule: &Rule,
    subcommand_path: &[String],
    user_argv: &[String],
    captures: &HashMap<String, String>,
) -> Result<Vec<String>, GuardError> {
    let mut argv: Vec<String> = Vec::new();

    if let Action::Run { args, .. } = &rule.action {
        for arg in args {
            argv.push(substitute_arg_template(arg, captures)?);
        }
    }

    for arg in &rule.pre_args {
        argv.push(substitute_arg_template(arg, captures)?);
    }

    let cmd_name = rule.command_name();
    let mut i: usize = 0;
    if let Some(cmd) = cmd_name
        && i < user_argv.len()
        && user_argv[i] == cmd
    {
        i += 1;
    }

    let mut sub_level: usize = 0;
    let mut subs: &[Subcommand] = &rule.subcommands;

    while i < user_argv.len() && sub_level < subcommand_path.len() {
        let token = &user_argv[i];
        i += 1;

        if token == &subcommand_path[sub_level] {
            if let Some(sub) = find_sub_by_name(subs, &subcommand_path[sub_level]) {
                argv.push(sub.name.clone());
                for arg in &sub.pre_args {
                    argv.push(substitute_arg_template(arg, captures)?);
                }
                subs = &sub.subcommands;
            }
            sub_level += 1;
        } else {
            argv.push(token.clone());
        }
    }

    if i < user_argv.len() {
        argv.extend_from_slice(&user_argv[i..]);
    }

    Ok(argv)
}

fn action_run(
    binary: &str,
    argv: &[String],
    implicit_symlinks: bool,
    timeout: &Duration,
) -> Result<i32, GuardError> {
    let resolved = resolve_binary(binary, implicit_symlinks)?;

    // Preserve original binary name as argv[0] so multi-call binaries
    // (coreutils, busybox, etc) dispatch to correct subcommand.
    let binary_name = Path::new(binary)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("ssh-guard-cmd")
        .to_string();

    let mut cmd = std::process::Command::new(&resolved);
    cmd.arg0(binary_name);
    cmd.args(argv);
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    // Put child in its own process group so we can kill entire
    // group (including grandchildren) on timeout instead of leaving orphans.
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| GuardError::Action(format!("cannot spawn '{resolved}': {e}")))?;

    let start = Instant::now();
    let timeout_dur = std::time::Duration::from_millis(timeout.millis);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(1)),
            Ok(None) => {
                if start.elapsed() > timeout_dur {
                    // Negative PID targets process group in kill(2).
                    let Ok(child_pid) = i32::try_from(child.id()) else {
                        let _ = child.wait();
                        return Err(GuardError::Action(format!(
                            "child pid '{}' exceeds supported range",
                            child.id()
                        )));
                    };
                    let pid = nix::unistd::Pid::from_raw(-child_pid);
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

#[cfg(test)]
#[coverage(off)]
mod tests {
    use crate::config::arg::ArgStyle;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::*;

    // =====================================================================
    // Self-exec subprocess fixtures
    // =====================================================================
    // `action_run` tests need child process that exits 0, and outlives 1ms timeout.
    // Do that without host tools and without writing + exec'ing throwaway temp.
    //
    // So execute test harness binary itself and pass `--exact <test path>` so child runs
    // exactly one helper test below, then exits:
    //   - `subprocess_helper_success` -> exits 0 immediately
    //   - `subprocess_helper_sleep`   -> sleeps 100ms

    fn test_binary_path() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    fn test_binary_args(test_name: &str) -> Vec<String> {
        vec!["--exact".into(), test_name.into()]
    }

    #[test]
    fn subprocess_helper_success() {}

    #[test]
    fn subprocess_helper_sleep() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    fn make_systemctl_rule() -> Rule {
        Rule {
            action: Action::Run {
                binary: "/opt/test/bin/systemctl".into(),
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
                binary: "/opt/test/bin/journalctl".into(),
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
        let user_argv = vec![
            "systemctl".to_string(),
            "status".to_string(),
            "angrr".to_string(),
        ];
        let subcommand_path = vec!["status".to_string()];

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

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

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

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
        let user_argv = vec![
            "journalctl".to_string(),
            "-u".to_string(),
            "sshd".to_string(),
            "-n".to_string(),
            "10".to_string(),
        ];
        let subcommand_path: Vec<String> = vec![];

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

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

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

        assert_eq!(result, vec!["--no-pager".to_string()]);
    }

    #[test]
    fn test_build_command_nested_subcommands() {
        let rule = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/git".into(),
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

        let user_argv = vec![
            "git".to_string(),
            "remote".to_string(),
            "add".to_string(),
            "origin".to_string(),
        ];
        let subcommand_path = vec!["remote".to_string(), "add".to_string()];

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

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
        let rule = make_systemctl_rule();
        let user_argv = vec![
            "other".to_string(),
            "systemctl".to_string(),
            "status".to_string(),
            "angrr".to_string(),
        ];
        let subcommand_path = vec!["status".to_string()];

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

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

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

        assert_eq!(result, vec!["--no-pager".to_string()]);
    }

    #[test]
    fn test_build_command_action_args_before_subcommand() {
        let rule = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/cmd".to_string(),
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
        let result = build_argv(&rule, &sub_path, &user_argv, &HashMap::new()).unwrap();
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
        let rule = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/git".to_string(),
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
        let result = build_argv(&rule, &sub_path, &user_argv, &HashMap::new()).unwrap();
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
        let rule = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/cmd".to_string(),
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
        let result = build_argv(&rule, &sub_path, &user_argv, &HashMap::new()).unwrap();
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
        let rule = make_systemctl_rule();
        let user_argv = vec![
            "systemctl".into(),
            "-H".into(),
            "host.example.com".into(),
            "status".into(),
            "sshd".into(),
        ];
        let sub_path = vec!["status".into()];
        let result = build_argv(&rule, &sub_path, &user_argv, &HashMap::new()).unwrap();
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
    fn test_build_command_no_command_name() {
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

        let result = build_argv(&rule, &subcommand_path, &user_argv, &HashMap::new()).unwrap();

        assert_eq!(result, vec!["somecmd".to_string()]);
    }

    #[test]
    fn test_build_command_no_action_args_with_subcommand() {
        let rule = Rule {
            action: Action::Run {
                binary: "/opt/test/bin/cmd".to_string(),
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
        let result = build_argv(&rule, &sub_path, &user_argv, &HashMap::new()).unwrap();
        assert_eq!(result, vec!["sub".to_string(), "--internal".to_string()]);
    }

    #[test]
    fn test_resolve_binary_implicit_symlinks_true() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("mybinary");
        std::fs::write(&bin_path, "").unwrap();
        let result = resolve_binary(bin_path.to_str().unwrap(), true).unwrap();
        assert!(result.contains("mybinary"));
    }

    #[test]
    fn test_resolve_binary_implicit_symlinks_false_not_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("mybinary");
        std::fs::write(&bin_path, "").unwrap();
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

    #[test]
    fn test_action_run_success() {
        let bin_path = test_binary_path();
        let argv = test_binary_args("kinds::run::tests::subprocess_helper_success");
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
        let bin_path = test_binary_path();
        let argv = test_binary_args("kinds::run::tests::subprocess_helper_sleep");
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

    #[test]
    fn test_run_execute_with_run_action() {
        let bin_path = test_binary_path();
        let config = crate::config::Config::default();
        let rule = Rule {
            action: Action::Run {
                binary: bin_path.to_str().unwrap().into(),
                args: test_binary_args("kinds::run::tests::subprocess_helper_success"),
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
        };
        let Action::Run {
            binary,
            args,
            timeout,
        } = &rule.action
        else {
            panic!("expected Run action");
        };
        let kind = Run {
            binary,
            args,
            timeout,
        };
        let captures = HashMap::new();
        let ctx = ExecCtx {
            config: &config,
            rule: &rule,
            subcommand_path: &[],
            captures: &captures,
            user_argv: &[],
        };
        let result = kind.execute(&ctx);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_substitute_plain_name() {
        let mut captures = HashMap::new();
        captures.insert("depth".to_string(), "2".to_string());
        let result = substitute_arg_template("-d{depth}", &captures).unwrap();
        assert_eq!(result, "-d2");
    }

    #[test]
    fn test_substitute_multiple_placeholders() {
        let mut captures = HashMap::new();
        captures.insert("unit".to_string(), "sshd".to_string());
        let result = substitute_arg_template("{unit}.service", &captures).unwrap();
        assert_eq!(result, "sshd.service");
    }

    #[test]
    fn test_substitute_default_used_when_capture_missing() {
        let captures = HashMap::new();
        let result = substitute_arg_template("{depth:-1}", &captures).unwrap();
        assert_eq!(result, "1");
    }

    #[test]
    fn test_substitute_capture_wins_over_default() {
        let mut captures = HashMap::new();
        captures.insert("depth".to_string(), "3".to_string());
        let result = substitute_arg_template("{depth:-1}", &captures).unwrap();
        assert_eq!(result, "3");
    }

    #[test]
    fn test_substitute_missing_capture_no_default_fails() {
        let captures = HashMap::new();
        let result = substitute_arg_template("-d{depth}", &captures);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing capture 'depth'"), "{err}");
    }

    #[test]
    fn test_substitute_literal_without_placeholders() {
        let captures = HashMap::new();
        let result = substitute_arg_template("--no-pager", &captures).unwrap();
        assert_eq!(result, "--no-pager");
    }

    #[test]
    fn test_substitute_unclosed_brace_is_literal() {
        let captures = HashMap::new();
        let result = substitute_arg_template("we{ird", &captures).unwrap();
        assert_eq!(result, "we{ird");
    }

    #[test]
    fn test_substitute_escaped_brace_is_literal() {
        let mut captures = HashMap::new();
        captures.insert("depth".to_string(), "2".to_string());
        let result = substitute_arg_template(r"\{depth}", &captures).unwrap();
        assert_eq!(result, "{depth}");
    }

    #[test]
    fn test_substitute_escaped_brace_mixed_with_placeholder() {
        let mut captures = HashMap::new();
        captures.insert("depth".to_string(), "2".to_string());
        let result = substitute_arg_template(r"-d{depth} \{literal\}", &captures).unwrap();
        assert_eq!(result, "-d2 {literal}");
    }

    #[test]
    fn test_substitute_escaped_backslash() {
        let captures = HashMap::new();
        let result = substitute_arg_template(r"a\\b\{x}", &captures).unwrap();
        assert_eq!(result, r"a\b{x}");
    }

    #[test]
    fn test_substitute_trailing_backslash_is_literal() {
        let captures = HashMap::new();
        let result = substitute_arg_template("path\\", &captures).unwrap();
        assert_eq!(result, "path\\");
    }

    #[test]
    fn test_build_command_substitutes_action_args_and_pre_args() {
        let mut rule = make_simple_rule();
        if let Action::Run { args, .. } = &mut rule.action {
            args.clear();
            args.push("-d{depth:-2}".into());
        }
        rule.args = vec!["{any}".into()];
        rule.subcommands = vec![Subcommand {
            name: "top".into(),
            arg_style: None,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec!["--root={root:-/srv}".into()],
            subcommands: vec![],
        }];

        let mut captures = HashMap::new();
        captures.insert("root".to_string(), "/data".to_string());

        let user_argv = vec!["journalctl".to_string(), "top".to_string()];
        let result = build_argv(&rule, &["top".to_string()], &user_argv, &captures).unwrap();
        assert_eq!(
            result,
            vec![
                "-d2".to_string(),
                "top".to_string(),
                "--root=/data".to_string(),
            ]
        );
    }

    #[test]
    fn test_build_command_missing_capture_is_error() {
        let mut rule = make_simple_rule();
        if let Action::Run { args, .. } = &mut rule.action {
            args.clear();
            args.push("-d{depth}".into());
        }
        rule.args = vec!["{any}".into()];

        let user_argv = vec!["journalctl".to_string(), "/var".to_string()];
        let result = build_argv(&rule, &[], &user_argv, &HashMap::new());
        assert!(result.is_err());
    }
}
