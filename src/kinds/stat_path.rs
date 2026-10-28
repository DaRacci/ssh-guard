use std::fs::symlink_metadata;
use std::path::Path;

use crate::config::Config;
use crate::errors::GuardError;
use crate::kinds::support::{lookup_capture, resolve_named_root_set, resolve_within_roots};
use crate::kinds::{ExecCtx, RuleKind};

pub(super) struct StatPath<'a> {
    pub(super) path_capture: &'a str,
    pub(super) root_set: &'a str,
}

fn action_stat_path(
    path_str: &str,
    root_set: &[String],
    _config: &Config,
) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, root_set)?;

    let meta = symlink_metadata(path)?;
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

impl RuleKind for StatPath<'_> {
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
        action_stat_path(path, selected_roots, ctx.config)?;
        Ok(0)
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{create_dir, write};

    use nix::sys::stat::Mode;

    use super::*;
    use crate::config::Config;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::rule::Rule;
    use crate::kinds::{ExecCtx, RuleKind};

    fn rule(action: Action) -> Rule {
        Rule {
            action,
            command: Some("stat".into()),
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
    fn test_action_stat_path_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("afile.txt");
        write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(file_path.to_str().unwrap(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub_dir = dir.path().join("subdir");
        create_dir(&sub_dir).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(&sub_dir.to_string_lossy(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real.txt");
        write(&real_file, "data").unwrap();
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(link_path.to_str().unwrap(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_other_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo_path = dir.path().join("test_fifo");
        nix::unistd::mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_stat_path(fifo_path.to_str().unwrap(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_stat_path_outside_roots_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real_file = outside.path().join("secret.txt");
        write(&real_file, "data").unwrap();
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let err =
            action_stat_path(link_path.to_str().unwrap(), &config.roots, &config).unwrap_err();
        assert!(
            matches!(err, GuardError::PathNotAllowed(_)),
            "expected PathNotAllowed, got {err:?}"
        );
    }

    #[test]
    fn test_action_stat_path_parent_traversal_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real_file = outside.path().join("secret.txt");
        write(&real_file, "data").unwrap();

        let traversal = dir.path().join("..").join("..").join("..").join("..");
        let target = traversal.join(real_file.strip_prefix("/").unwrap());

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let err = action_stat_path(target.to_str().unwrap(), &config.roots, &config).unwrap_err();
        assert!(
            matches!(err, GuardError::PathNotAllowed(_)),
            "expected PathNotAllowed, got {err:?}"
        );
    }

    #[test]
    fn test_execute_stat_path_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("stat.txt");
        write(&file_path, "data").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::StatPath {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = StatPath {
            path_capture: "path",
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_execute_stat_path_missing_capture() {
        let config = Config::default();
        let rule = rule(Action::StatPath {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = StatPath {
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
            "expected missing capture error, got {result:?}"
        );
    }

    #[test]
    fn test_execute_stat_path_unknown_root_set() {
        let config = Config::default();
        let rule = rule(Action::StatPath {
            path_capture: "path".into(),
            root_set: "custom".into(),
        });
        let kind = StatPath {
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
