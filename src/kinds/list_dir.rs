use std::fs::read_dir;
use std::path::Path;

use crate::config::Config;
use crate::errors::GuardError;
use crate::kinds::support::{lookup_capture, resolve_named_root_set, resolve_within_roots};
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct ListDir<'a> {
    pub(super) path_capture: &'a str,
    pub(super) root_set: &'a str,
}

fn action_list_dir(
    path_str: &str,
    root_set: &[String],
    _config: &Config,
) -> Result<(), GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, root_set)?;

    let mut entries: Vec<_> = read_dir(path)
        .map_err(|e| {
            GuardError::Action(format!("cannot read directory '{}': {e}", path.display()))
        })?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name())
        .collect();

    entries.sort();
    for entry in entries {
        println!("{}", entry.to_string_lossy());
    }
    Ok(())
}

impl RuleKind for ListDir<'_> {
    fn name(&self) -> &'static str {
        "list_dir"
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
        action_list_dir(path, selected_roots, ctx.config)?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{create_dir, write};

    use super::*;
    use crate::config::Config;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::rule::Rule;
    use crate::kinds::{ExecCtx, RuleKind};

    fn rule(action: Action) -> Rule {
        Rule {
            action,
            command: Some("ls".into()),
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
    fn test_action_list_dir_success() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path().join("a.txt"), "").unwrap();
        write(dir.path().join("b.txt"), "").unwrap();
        create_dir(dir.path().join("sub")).unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_list_dir(dir.path().to_str().unwrap(), &config.roots, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_list_dir_success() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path().join("a.txt"), "").unwrap();
        write(dir.path().join("b.txt"), "").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::ListDir {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = ListDir {
            path_capture: "path",
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), dir.path().to_string_lossy().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_execute_list_dir_missing_capture() {
        let config = Config::default();
        let rule = rule(Action::ListDir {
            path_capture: "path".into(),
            root_set: "roots".into(),
        });
        let kind = ListDir {
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
    fn test_execute_list_dir_unknown_root_set() {
        let config = Config::default();
        let rule = rule(Action::ListDir {
            path_capture: "path".into(),
            root_set: "custom".into(),
        });
        let kind = ListDir {
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
