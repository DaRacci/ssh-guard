use std::collections::HashMap;
use std::path::Path;

use crate::config::Config;
use crate::errors::GuardError;
use crate::path_security::ensure_path_in_roots;

pub(crate) fn resolve_within_roots(
    input_path: &Path,
    root_set: &[String],
) -> Result<(), GuardError> {
    ensure_path_in_roots(input_path, root_set, true).map_err(GuardError::PathNotAllowed)
}

pub(crate) fn resolve_named_root_set<'a>(
    config: &'a Config,
    root_set: &str,
) -> Result<&'a [String], GuardError> {
    config
        .root_set_paths(root_set)
        .ok_or_else(|| GuardError::Action(format!("unknown root set '{root_set}'")))
}

/// Resolve a capture reference from the match captures.
///
/// File-action fields may be written with or without template braces,
/// both `"path"` and `"{path}"` resolve to the capture stored under key `path`.
///
/// If the exact key is missing, the braced form is also tried so `{path}`-style references match contract-named captures.
pub(crate) fn lookup_capture<'a, S: ::std::hash::BuildHasher>(
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::write;

    use super::*;

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

    #[test]
    fn test_lookup_capture_accepts_braced_reference() {
        let mut captures = HashMap::new();
        captures.insert("path".to_string(), "/tmp/data.txt".to_string());

        assert_eq!(
            lookup_capture(&captures, "{path}").map(String::as_str),
            Some("/tmp/data.txt")
        );
    }

    #[test]
    fn test_lookup_capture_rejects_escaped_brace_reference() {
        let mut captures = HashMap::new();
        captures.insert("path".to_string(), "/etc/hostname".to_string());

        assert!(lookup_capture(&captures, r"\{path}").is_none());
        assert!(lookup_capture(&captures, "{path}").is_some());
        assert!(lookup_capture(&captures, "path").is_some());
    }

    #[test]
    fn test_lookup_capture_rejects_escaped_or_embedded_backslash() {
        let mut captures = HashMap::new();
        captures.insert("path".to_string(), "/etc/hostname".to_string());

        assert!(lookup_capture(&captures, r"{path\}").is_none());
        assert!(lookup_capture(&captures, r"\\{path}").is_none());
        assert!(lookup_capture(&captures, "{pa}th}").is_none());
    }
}
