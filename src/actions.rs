use std::collections::{HashMap, VecDeque};
use std::fs::{File, metadata, read_dir, read_to_string, symlink_metadata};
use std::io::BufRead;
use std::path::Path;

use crate::config::Config;
use crate::config::action::Action;
use crate::config::rule::Rule;
use crate::errors::GuardError;
use crate::path_security::ensure_path_in_roots;

fn resolve_within_roots(input_path: &Path, root_set: &[String]) -> Result<(), GuardError> {
    ensure_path_in_roots(input_path, root_set, true).map_err(GuardError::PathNotAllowed)
}

fn resolve_named_root_set<'a>(
    config: &'a Config,
    root_set: &str,
) -> Result<&'a [String], GuardError> {
    config
        .root_set_paths(root_set)
        .ok_or_else(|| GuardError::Action(format!("unknown root set '{root_set}'")))
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

/// Read up to `max_lines` lines from the tail of `path`, preserving order.
///
/// `lines` is clamped to `max_lines`; a count of zero yields nothing.
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
        .map(|e| e.file_name())
        .collect();

    entries.sort();
    for entry in entries {
        println!("{}", entry.to_string_lossy());
    }
    Ok(())
}

/// Resolve a capture reference from the match captures.
///
/// File-action fields may be written with or without template braces: both
/// `"path"` and `"{path}"` resolve to the capture stored under key `path`.
/// If the exact key is missing, the braced form is also tried so
/// `{path}`-style references match contract-named captures.
fn lookup_capture<'a, S: ::std::hash::BuildHasher>(
    captures: &'a HashMap<String, String, S>,
    reference: &str,
) -> Option<&'a String> {
    if let Some(v) = captures.get(reference) {
        return Some(v);
    }

    let trimmed = reference.trim();
    let bytes = trimmed.as_bytes();

    if !(trimmed.len() > 2
        && bytes[0] == b'{'
        && bytes[trimmed.len() - 1] == b'}'
        && !crate::engine::parse::is_escaped(trimmed, trimmed.len() - 1))
    {
        return None;
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.contains(['{', '}', '\\']) {
        return None;
    }
    captures.get(inner)
}

pub(crate) fn execute_read_file<S: ::std::hash::BuildHasher>(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String, S>,
) -> Result<(), GuardError> {
    if let Action::ReadFile {
        path_capture,
        root_set,
    } = action
    {
        let path = lookup_capture(captures, path_capture).ok_or_else(|| {
            GuardError::Action(format!(
                "missing capture '{path_capture}' (rule args must capture it, e.g. {{{path_capture}:string}} or a contract named '{path_capture}')"
            ))
        })?;
        let selected_roots = resolve_named_root_set(config, root_set)?;
        action_read_file(path, selected_roots, config)?;
        Ok(())
    } else {
        Err(GuardError::Action("expected ReadFile action".into()))
    }
}

pub(crate) fn execute_tail_file<S: ::std::hash::BuildHasher>(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String, S>,
) -> Result<(), GuardError> {
    if let Action::TailFile {
        path_capture,
        lines_capture,
        default_lines,
        root_set,
    } = action
    {
        let path = lookup_capture(captures, path_capture).ok_or_else(|| {
            GuardError::Action(format!(
                "missing capture '{path_capture}' (rule args must capture it, e.g. {{{path_capture}:string}} or a contract named '{path_capture}')"
            ))
        })?;
        let lines = lines_capture
            .as_ref()
            .and_then(|lc| lookup_capture(captures, lc))
            .and_then(|l| l.parse::<usize>().ok())
            .unwrap_or(*default_lines);
        let selected_roots = resolve_named_root_set(config, root_set)?;
        for line in action_tail_file(path, lines, selected_roots, config)? {
            print!("{line}");
        }
        Ok(())
    } else {
        Err(GuardError::Action("expected TailFile action".into()))
    }
}

pub(crate) fn execute_stat_path<S: ::std::hash::BuildHasher>(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String, S>,
) -> Result<(), GuardError> {
    if let Action::StatPath {
        path_capture,
        root_set,
    } = action
    {
        let path = lookup_capture(captures, path_capture).ok_or_else(|| {
            GuardError::Action(format!(
                "missing capture '{path_capture}' (rule args must capture it, e.g. {{{path_capture}:string}} or a contract named '{path_capture}')"
            ))
        })?;
        let selected_roots = resolve_named_root_set(config, root_set)?;
        action_stat_path(path, selected_roots, config)?;
        Ok(())
    } else {
        Err(GuardError::Action("expected StatPath action".into()))
    }
}

pub(crate) fn execute_list_dir<S: ::std::hash::BuildHasher>(
    config: &Config,
    action: &Action,
    captures: &HashMap<String, String, S>,
) -> Result<(), GuardError> {
    if let Action::ListDir {
        path_capture,
        root_set,
    } = action
    {
        let path = lookup_capture(captures, path_capture).ok_or_else(|| {
            GuardError::Action(format!(
                "missing capture '{path_capture}' (rule args must capture it, e.g. {{{path_capture}:string}} or a contract named '{path_capture}')"
            ))
        })?;
        let selected_roots = resolve_named_root_set(config, root_set)?;
        action_list_dir(path, selected_roots, config)?;
        Ok(())
    } else {
        Err(GuardError::Action("expected ListDir action".into()))
    }
}

pub(crate) fn execute_show_help(config: &Config) {
    print!("{}", config.global.help_text);
}

/// Build the executable argv for a rule without running the binary.
///
/// Test and audit seam over `kinds::run::build_argv`: same template substitution
/// and fail-closed behavior, no side effects.
///
/// # Errors
///
/// Returns an error when a `{name}` placeholder in the rule's config-sourced
/// args has no matching capture and no `{name:-default}` fallback.
pub fn execute_argv_for_test<S: ::std::hash::BuildHasher>(
    rule: &Rule,
    subcommand_path: &[String],
    captures: &HashMap<String, String, S>,
    user_argv: &[String],
) -> Result<Vec<String>, GuardError> {
    let captures: HashMap<String, String> = captures
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    crate::kinds::run::build_argv(rule, subcommand_path, user_argv, &captures)
}

/// Execute matched rule action.
///
/// Returns the process exit code to surface to the caller.
///
/// # Errors
///
/// Returns `GuardError` when action execution fails, required captures are missing,
/// or the rule contains an unsupported action payload.
pub fn execute<S: ::std::hash::BuildHasher>(
    config: &Config,
    rule: &Rule,
    subcommand_path: &[String],
    captures: &HashMap<String, String, S>,
    user_argv: &[String],
) -> Result<i32, GuardError> {
    let captures: HashMap<String, String> = captures
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let ctx = crate::kinds::ExecCtx {
        config,
        rule,
        subcommand_path,
        captures: &captures,
        user_argv,
    };
    crate::kinds::kind_for(&rule.action).execute(&ctx)
}

#[cfg(test)]
mod tests {
    use crate::config::arg::ArgStyle;
    use crate::config::duration::Duration;
    use crate::config::global::Global;
    use nix::sys::stat::Mode;
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::fs::{create_dir, write};
    use std::path::PathBuf;

    use super::*;

    fn test_binary_path() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    fn test_binary_args(test_name: &str) -> Vec<String> {
        vec!["--exact".into(), test_name.into()]
    }

    /// File content with `count` numbered lines, each newline-terminated.
    fn numbered_lines(count: usize) -> String {
        let mut content = String::new();
        for i in 0..count {
            let _ = writeln!(&mut content, "line{i}");
        }
        content
    }

    fn as_lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    // -----------------------------------------------------------------------
    // Tests for resolve_within_roots
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_within_roots_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        write(&file_path, "hello").unwrap();

        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(resolve_within_roots(&file_path, &roots).is_ok());
    }

    #[test]
    fn test_resolve_within_roots_outside() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let file_path = outside.path().join("test.txt");
        write(&file_path, "hello").unwrap();

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
    // Tests for action_read_file
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Tests for action_tail_file
    // -----------------------------------------------------------------------

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
        // Path within roots but file doesn't exist -> tail fails
        // Create a directory, tail will fail on it since it's not a regular file
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

        // More requested than present -> every line, original order.
        assert_eq!(
            read_tail_lines(&file_path, 10, 100).unwrap(),
            as_lines(&["line0\n", "line1\n", "line2\n", "line3\n", "line4\n"])
        );
        // Exactly the file length.
        assert_eq!(
            read_tail_lines(&file_path, 5, 100).unwrap(),
            as_lines(&["line0\n", "line1\n", "line2\n", "line3\n", "line4\n"])
        );
        // Last two, order preserved.
        assert_eq!(
            read_tail_lines(&file_path, 2, 100).unwrap(),
            as_lines(&["line3\n", "line4\n"])
        );
        // Single line.
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

        // A final line without a trailing newline is still a line.
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

        // CRLF is not translated: bytes come back as-is.
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

    // -----------------------------------------------------------------------
    // Tests for action_stat_path
    // -----------------------------------------------------------------------

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
        // fifo cleaned up when TempDir drops
    }

    #[test]
    fn test_action_stat_path_outside_roots_rejected() {
        // A symlink inside the root pointing to a file outside the root must be
        // rejected: the full resolved target is outside the roots even though the
        // symlink's parent is inside.
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
        // A `..` traversal whose parent resolves inside the root but whose full
        // path resolves outside must be rejected.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real_file = outside.path().join("secret.txt");
        write(&real_file, "data").unwrap();

        // Build a path inside `dir` that traverses up to the outside file.
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

    // -----------------------------------------------------------------------
    // Tests for action_list_dir
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Tests for execute_read_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_read_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data.txt");
        write(&file_path, "content").unwrap();

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
        assert!(result.is_ok());
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
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "data".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_read_file(&config, &action, &captures);
        assert!(
            result.is_ok(),
            "expected named root set to work, got {result:?}"
        );
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
        write(&file_path, "line1\nline2\n").unwrap();

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
        assert!(result.is_ok());
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
        write(&file_path, "line1\nline2\n").unwrap();

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
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_tail_file_lines_from_default() {
        // lines_capture is Some but the capture key doesn't exist in captures
        // → falls back to default_lines
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
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("missing_lines".into()),
            default_lines: 5,
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_tail_file(&config, &action, &captures);
        assert!(result.is_ok());
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
        write(&file_path, "data").unwrap();

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
        assert!(result.is_ok());
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
        write(dir.path().join("a.txt"), "").unwrap();
        write(dir.path().join("b.txt"), "").unwrap();

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
        assert!(result.is_ok());
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
    // Tests for lookup_capture brace tolerance
    // -----------------------------------------------------------------------

    #[test]
    fn test_lookup_capture_accepts_braced_reference() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data.txt");
        write(&file_path, "content").unwrap();

        let config = Config {
            roots: vec![dir.path().to_string_lossy().to_string()],
            ..Default::default()
        };
        let action = Action::ReadFile {
            path_capture: "{path}".into(),
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());

        let result = execute_read_file(&config, &action, &captures);
        assert!(result.is_ok());
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
        let action = Action::TailFile {
            path_capture: "path".into(),
            lines_capture: Some("n".into()),
            default_lines: 10,
            root_set: "roots".into(),
        };
        let mut captures = HashMap::new();
        captures.insert("path".into(), file_path.to_str().unwrap().to_string());
        captures.insert("n".into(), "2".into());

        let result = execute_tail_file(&config, &action, &captures);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_capture_error_names_field_and_fix() {
        let config = Config::default();
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        };
        let captures = HashMap::new();
        let result = execute_read_file(&config, &action, &captures);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing capture 'path'") && err.contains("{path:string}"),
            "expected actionable error, got: {err}"
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
        execute_show_help(&config);
    }

    // -----------------------------------------------------------------------
    // Tests for execute (dispatch)
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_dispatches_run() {
        // Child = this test binary re-exec'd to run `subprocess_helper_success`.
        let bin_path = test_binary_path();

        let config = Config::default();
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
        write(&file_path, "line1\nline2\n").unwrap();

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
        write(&file_path, "data").unwrap();

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
        write(dir.path().join("f1.txt"), "").unwrap();

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

    #[test]
    fn test_lookup_capture_rejects_escaped_brace_reference() {
        let mut captures = HashMap::new();
        captures.insert("path".to_string(), "/etc/hostname".to_string());
        // A backslash-escaped opening brace is not a braced reference.
        assert!(lookup_capture(&captures, r"\{path}").is_none());
        assert!(lookup_capture(&captures, "{path}").is_some());
        assert!(lookup_capture(&captures, "path").is_some());
    }

    #[test]
    fn test_lookup_capture_rejects_escaped_or_embedded_backslash() {
        let mut captures = HashMap::new();
        captures.insert("path".to_string(), "/etc/hostname".to_string());
        // Escaped closing brace, doubled backslash, and braces inside the name are all not braced references.
        assert!(lookup_capture(&captures, r"{path\}").is_none());
        assert!(lookup_capture(&captures, r"\\{path}").is_none());
        assert!(lookup_capture(&captures, "{pa}th}").is_none());
    }
}
