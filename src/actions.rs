use std::collections::HashMap;

use crate::config::Config;
use crate::config::rule::Rule;
use crate::errors::GuardError;

/// Build the executable argv for a rule without running the binary.
///
/// Test and audit seam over `kinds::run::build_argv`: same template substitution
/// and fail-closed behavior, no side effects.
///
/// # Errors
///
/// Returns an error when a `{name}` placeholder in the rule's config-sourced
/// args has no matching capture and no `{name:-default}` fallback.
#[allow(clippy::implicit_hasher)]
pub fn execute_argv_for_test(
    rule: &Rule,
    subcommand_path: &[String],
    captures: &HashMap<String, String>,
    user_argv: &[String],
) -> Result<Vec<String>, GuardError> {
    crate::kinds::run::build_argv(rule, subcommand_path, user_argv, captures)
}

/// Execute matched rule action.
///
/// Returns the process exit code to surface to the caller.
///
/// # Errors
///
/// Returns `GuardError` when action execution fails or required captures are missing.
#[allow(clippy::implicit_hasher)]
pub fn execute(
    config: &Config,
    rule: &Rule,
    subcommand_path: &[String],
    captures: &HashMap<String, String>,
    user_argv: &[String],
) -> Result<i32, GuardError> {
    let ctx = crate::kinds::ExecCtx {
        config,
        rule,
        subcommand_path,
        captures,
        user_argv,
    };
    crate::kinds::kind_for(&rule.action).execute(&ctx)
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use std::collections::HashMap;
    use std::fs::write;
    use std::path::PathBuf;

    use super::*;
    use crate::config::Config;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::duration::Duration;
    use crate::config::global::Global;
    use crate::config::rule::Rule;

    fn test_binary_path() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    fn test_binary_args(test_name: &str) -> Vec<String> {
        vec!["--exact".into(), test_name.into()]
    }

    fn rule(action: Action, command: Option<&str>) -> Rule {
        Rule {
            action,
            command: command.map(str::to_owned),
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
    fn test_execute_dispatches_run() {
        let bin_path = test_binary_path();

        let config = Config::default();
        let rule = rule(
            Action::Run {
                binary: bin_path.to_str().unwrap().into(),
                args: test_binary_args("kinds::run::tests::subprocess_helper_success"),
                timeout: Duration { millis: 5000 },
            },
            None,
        );
        let captures = HashMap::new();
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_read_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec.txt");
        write(&file_path, "content").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(
            Action::ReadFile {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            Some("cat"),
        );
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_tail_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec.log");
        write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(
            Action::TailFile {
                path_capture: "path".into(),
                lines_capture: None,
                default_lines: 10,
                root_set: "roots".into(),
            },
            Some("tail"),
        );
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_stat_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exec_stat.txt");
        write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(
            Action::StatPath {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            Some("stat"),
        );
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_execute_dispatches_list_dir() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path().join("f1.txt"), "").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(
            Action::ListDir {
                path_capture: "path".into(),
                root_set: "roots".into(),
            },
            Some("ls"),
        );
        let mut captures = HashMap::new();
        captures.insert("path".into(), dir.path().to_string_lossy().to_string());
        let result = execute(&config, &rule, &[], &captures, &[]);
        assert_eq!(result.unwrap(), 0);
    }
}
