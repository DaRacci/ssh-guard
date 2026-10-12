use std::collections::VecDeque;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;

use crate::config::Config;
use crate::errors::GuardError;
use crate::kinds::support::{lookup_capture, resolve_named_root_set, resolve_within_roots};
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct TailFile<'a> {
    pub(super) path_capture: &'a str,
    pub(super) lines_capture: Option<&'a str>,
    pub(super) default_lines: usize,
    pub(super) root_set: &'a str,
}

/// Read up to `max_lines` lines from the tail of `path`, preserving order.
///
/// `lines` is clamped to `max_lines`.
/// If `lines` is zero, an empty vector is returned.
fn read_tail_lines(path: &Path, lines: usize, max_lines: usize) -> Result<Vec<String>, GuardError> {
    let file = File::open(path).map_err(|e| GuardError::Action(format!("tail failed: {e}")))?;

    let lines = lines.min(max_lines);
    if lines == 0 {
        return Ok(Vec::new());
    }

    let mut reader = std::io::BufReader::new(file);
    let mut buf = String::new();
    let mut tail = VecDeque::with_capacity(lines);

    loop {
        buf.clear();
        let bytes_read = reader
            .read_line(&mut buf)
            .map_err(|e| GuardError::Action(format!("tail failed: {e}")))?;
        if bytes_read == 0 {
            break;
        }
        if tail.len() == lines {
            let _ = tail.pop_front();
        }
        tail.push_back(std::mem::take(&mut buf));
    }

    Ok(tail.into_iter().collect())
}

/// Return the last `lines` lines of `path_str`, after checking it lies within a configured root.
/// The caller is responsible for printing them.
fn action_tail_file(
    path_str: &str,
    lines: usize,
    root_set: &[String],
    config: &Config,
) -> Result<Vec<String>, GuardError> {
    let path = Path::new(path_str);
    resolve_within_roots(path, root_set)?;
    read_tail_lines(path, lines, config.global.max_tail_lines)
}

impl RuleKind for TailFile<'_> {
    fn name(&self) -> &'static str {
        "tail_file"
    }

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        let mut refs = vec![("path_capture", self.path_capture)];
        if let Some(lines_capture) = self.lines_capture {
            refs.push(("lines_capture", lines_capture));
        }
        refs
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
        let lines = self
            .lines_capture
            .and_then(|lines_capture| lookup_capture(ctx.captures, lines_capture))
            .and_then(|line| line.parse::<usize>().ok())
            .unwrap_or(self.default_lines);
        let selected_roots = resolve_named_root_set(ctx.config, self.root_set)?;
        for line in action_tail_file(path, lines, selected_roots, ctx.config)? {
            print!("{line}");
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::fs::{create_dir, write};

    use super::*;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::global::Global;
    use crate::config::rule::Rule;
    use crate::config::Config;
    use crate::kinds::{ExecCtx, RuleKind};

    fn rule(action: Action) -> Rule {
        Rule {
            action,
            command: Some("tail".into()),
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

    fn numbered_lines(count: usize) -> String {
        let mut content = String::new();
        for i in 0..count {
            let _ = writeln!(&mut content, "line{i}");
        }
        content
    }

    fn as_lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn test_action_tail_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.log");
        write(&file_path, "line1\nline2\nline3\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result =
            action_tail_file(file_path.to_str().unwrap(), 2, &config.roots, &config).unwrap();
        assert_eq!(result, as_lines(&["line2\n", "line3\n"]));
    }

    #[test]
    fn test_action_tail_file_failure() {
        let dir = tempfile::tempdir().unwrap();
        create_dir(dir.path().join("subdir")).unwrap();
        let bad_path = dir.path().join("subdir");

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result = action_tail_file(bad_path.to_str().unwrap(), 10, &config.roots, &config);
        assert!(
            matches!(&result, Err(GuardError::Action(msg)) if msg.contains("tail failed")),
            "expected tail failure, got {result:?}"
        );
    }

    #[test]
    fn test_action_tail_file_lines_capped() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("long.log");
        write(&file_path, numbered_lines(20)).unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 5,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };

        let result =
            action_tail_file(file_path.to_str().unwrap(), 100, &config.roots, &config).unwrap();
        assert_eq!(
            result,
            as_lines(&["line15\n", "line16\n", "line17\n", "line18\n", "line19\n"])
        );
    }

    #[test]
    fn test_read_tail_lines_counts_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("numbered.log");
        write(&file_path, numbered_lines(5)).unwrap();

        assert_eq!(
            read_tail_lines(&file_path, 10, 100).unwrap(),
            as_lines(&["line0\n", "line1\n", "line2\n", "line3\n", "line4\n"])
        );
        assert_eq!(
            read_tail_lines(&file_path, 5, 100).unwrap(),
            as_lines(&["line0\n", "line1\n", "line2\n", "line3\n", "line4\n"])
        );
        assert_eq!(
            read_tail_lines(&file_path, 2, 100).unwrap(),
            as_lines(&["line3\n", "line4\n"])
        );
        assert_eq!(
            read_tail_lines(&file_path, 1, 100).unwrap(),
            as_lines(&["line4\n"])
        );
    }

    #[test]
    fn test_read_tail_lines_zero_request_or_zero_cap_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("numbered.log");
        write(&file_path, numbered_lines(20)).unwrap();

        assert!(read_tail_lines(&file_path, 0, 100).unwrap().is_empty());
        assert!(read_tail_lines(&file_path, 10, 0).unwrap().is_empty());
    }

    #[test]
    fn test_read_tail_lines_cap_clamps_request() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("numbered.log");
        write(&file_path, numbered_lines(20)).unwrap();

        assert_eq!(
            read_tail_lines(&file_path, 100, 3).unwrap(),
            as_lines(&["line17\n", "line18\n", "line19\n"])
        );
    }

    #[test]
    fn test_read_tail_lines_empty_file_and_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();

        let empty = dir.path().join("empty.log");
        write(&empty, "").unwrap();
        assert!(read_tail_lines(&empty, 5, 100).unwrap().is_empty());

        let partial = dir.path().join("partial.log");
        write(&partial, "a\nb\nc").unwrap();
        assert_eq!(
            read_tail_lines(&partial, 2, 100).unwrap(),
            as_lines(&["b\n", "c"])
        );
        assert_eq!(read_tail_lines(&partial, 1, 100).unwrap(), as_lines(&["c"]));
    }

    #[test]
    fn test_read_tail_lines_preserves_blank_and_crlf_lines_verbatim() {
        let dir = tempfile::tempdir().unwrap();

        let blanks = dir.path().join("blanks.log");
        write(&blanks, "x\n\n   \ny\n").unwrap();
        assert_eq!(
            read_tail_lines(&blanks, 4, 100).unwrap(),
            as_lines(&["x\n", "\n", "   \n", "y\n"])
        );

        let crlf = dir.path().join("crlf.log");
        write(&crlf, "a\r\nb\r\nc\r\n").unwrap();
        assert_eq!(
            read_tail_lines(&crlf, 2, 100).unwrap(),
            as_lines(&["b\r\n", "c\r\n"])
        );
    }

    #[test]
    fn test_read_tail_lines_missing_file_is_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.log");

        let err = read_tail_lines(&missing, 10, 100).unwrap_err();
        assert!(
            matches!(err, GuardError::Action(ref msg) if msg.contains("tail failed")),
            "expected tail failure, got {err:?}"
        );
    }

    #[test]
    fn test_execute_tail_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "roots".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: None,
            default_lines: 10,
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_execute_tail_file_missing_capture() {
        let config = Config::default();
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "roots".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: None,
            default_lines: 10,
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
    fn test_execute_tail_file_unknown_root_set() {
        let config = Config::default();
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: None,
            default_lines: 10,
            root_set: "custom".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: None,
            default_lines: 10,
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

    #[test]
    fn test_execute_tail_file_lines_from_capture() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        write(&file_path, "line1\nline2\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("lines".into()),
            default_lines: 10,
            root_set: "roots".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: Some("lines"),
            default_lines: 10,
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        captures.insert("lines".into(), "1".into());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_execute_tail_file_lines_from_default() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        write(&file_path, "line1\n").unwrap();

        let config = Config {
            global: Global {
                max_tail_lines: 100,
                ..Global::default()
            },
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("missing_lines".into()),
            default_lines: 5,
            root_set: "roots".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: Some("missing_lines"),
            default_lines: 5,
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }

    #[test]
    fn test_lookup_capture_named_capture_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.log");
        write(&file_path, "l1\nl2\nl3\n").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let rule = rule(Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("n".into()),
            default_lines: 10,
            root_set: "roots".into(),
        });
        let kind = TailFile {
            path_capture: "path",
            lines_capture: Some("n"),
            default_lines: 10,
            root_set: "roots",
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        captures.insert("n".into(), "2".into());

        let ctx = ctx(&config, &rule, &captures);
        assert_eq!(kind.execute(&ctx).unwrap(), 0);
    }
}
