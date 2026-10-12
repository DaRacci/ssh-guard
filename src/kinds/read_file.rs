use std::fs::{metadata, read_to_string};
use std::path::Path;

use crate::config::Config;
use crate::errors::GuardError;
use crate::kinds::support::{lookup_capture, resolve_named_root_set, resolve_within_roots};
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct ReadFile<'a> {
    pub(super) path_capture: &'a str,
    pub(super) root_set: &'a str,
}

fn action_read_file(
    path_str: &str,
    root_set: &[String],
    config: &Config,
) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, root_set)?;

    let meta = metadata(path)?;
    if meta.len() > config.global.max_read_bytes as u64 {
        return Err(GuardError::Action(format!(
            "file '{}' is {} bytes, exceeds limit of {}",
            path.display(),
            meta.len(),
            config.global.max_read_bytes
        )));
    }

    let contents = read_to_string(path)?;
    print!("{contents}");
    Ok(())
}

impl RuleKind for ReadFile<'_> {
    fn name(&self) -> &'static str {
        "read_file"
    }

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        vec![("path_capture", self.path_capture)]
    }

    fn root_sets(&self) -> Vec<&str> {
        vec![self.root_set]
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        let path = lookup_capture(ctx.captures, self.path_capture).ok_or_else(|| {
            GuardError::Action(format!(
                "missing capture '{path_capture}' (rule args must capture it, e.g. {{{path_capture}:string}} or a contract named '{path_capture}')",
                path_capture = self.path_capture
            ))
        })?;
        let selected_roots = resolve_named_root_set(ctx.config, self.root_set)?;
        action_read_file(path, selected_roots, ctx.config)?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::write;

    use super::*;
    use crate::config::Config;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::global::Global;
    use crate::config::rule::Rule;
    use crate::kinds::{ExecCtx, RuleKind};

    fn rule(action: Action) -> Rule {
        Rule {
            action,
            command: Some("cat".into()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        }
    }

    fn ctx<'a>(
        config: &'a Config,
        rule: &'a Rule,
        captures: &'a HashMap<String, String>,
    ) -> ExecCtx<'a> {
        ExecCtx {
            config,
            rule,
            subcommand_path: &[],
            captures,
            user_argv: &[],
        }
    }

    #[test]
    fn test_action_read_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("readme.txt");
        write(&file_path, "hello world").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_read_file_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("large.txt");
        let big_content = "a".repeat(500);
        write(&file_path, &big_content).unwrap();

        let config = Config {
            global: Global {
                max_read_bytes: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config.roots, &config);
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
        write(&file_path, "secret").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_read_file(file_path.to_str().unwrap(), &config.roots, &config);
        assert!(
            matches!(&result, Err(GuardError::PathNotAllowed(_))),
            "expected PathNotAllowed, got {result:?}"
        );
    }

    #[test]
    fn test_execute_read_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data.txt");
        write(&file_path, "content").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = ReadFile {
            path_capture: "path",
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_execute_read_file_named_root_set_success() {
        let default_root = tempfile::tempdir().unwrap();
        let data_root = tempfile::tempdir().unwrap();
        let file_path = data_root.path().join("data.txt");
        write(&file_path, "content").unwrap();

        let config: Config = toml::from_str(&format!(
            r#"
roots = ["{}"]

[root_sets]
data = ["{}"]

[[rules]]
action = {{ type = "show_help" }}
"#,
            default_root.path().display(),
            data_root.path().display()
        ))
        .unwrap();
        let rule = rule(Action::ReadFile {
            path_capture: "path".into(),
            root_set: "data".into(),
        });
        let kind = ReadFile {
            path_capture: "path",
            root_set: "data",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_missing_capture_error_names_field_and_fix() {
        let config = Config::default();
        let rule = rule(Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = ReadFile {
            path_capture: "path",
            root_set: "roots",
        };
        let captures = HashMap::new();

        let ctx = ctx(&config, &rule, &captures);
        let result = kind.execute(&ctx);
        assert!(
            matches!(
                &result,
                Err(GuardError::Action(msg))
                    if msg
                        == "missing capture 'path' (rule args must capture it, e.g. {path:string} or a contract named 'path')"
            ),
            "expected actionable missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_read_file_unknown_root_set() {
        let config = Config::default();
        let rule = rule(Action::ReadFile {
            path_capture: "path".into(),
            root_set: "custom".into(),
        });
        let kind = ReadFile {
            path_capture: "path",
            root_set: "custom",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), "/some/path".into());

        let ctx = ctx(&config, &rule, &captures);
        let result = kind.execute(&ctx);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg == "unknown root set 'custom'"),
            "expected unknown root set error, got {result:?}"
        );
    }
}
