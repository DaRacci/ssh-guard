use std::path::{Component, Path, PathBuf};

fn resolve_existing_path(input_path: &Path) -> Result<PathBuf, String> {
    input_path
        .canonicalize()
        .map_err(|_| format!("cannot resolve path '{}'", input_path.display()))
}

fn resolve_path_allow_missing(input_path: &Path) -> Result<PathBuf, String> {
    let mut resolved = if input_path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory: {e}"))?
            .canonicalize()
            .map_err(|_| "cannot resolve current directory".to_string())?
    };

    for component in input_path.components() {
        match component {
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
        }

        match std::fs::symlink_metadata(&resolved) {
            Ok(_) => {
                resolved = resolved
                    .canonicalize()
                    .map_err(|_| format!("cannot resolve path '{}'", resolved.display()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(format!("cannot resolve path '{}'", resolved.display()));
            }
        }
    }

    Ok(resolved)
}

pub(crate) fn ensure_path_in_roots(
    input_path: &Path,
    roots: &[String],
    must_exist: bool,
) -> Result<(), String> {
    let resolved = if must_exist {
        resolve_existing_path(input_path)?
    } else {
        resolve_path_allow_missing(input_path)?
    };

    for root_str in roots {
        let root_path = Path::new(root_str);
        if resolved.starts_with(root_path) {
            return Ok(());
        }
    }

    Err(format!(
        "path '{}' not within any allowed root",
        resolved.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_path_in_roots;
    use std::fs::{create_dir_all, write};
    use std::path::Path;

    #[test]
    fn test_ensure_path_in_roots_existing_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("ok.txt");
        write(&file_path, "ok").unwrap();
        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(ensure_path_in_roots(Path::new(&file_path), &roots, true).is_ok());
    }

    #[test]
    fn test_ensure_path_in_roots_missing_allowed_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = dir.path().join("uploads");
        create_dir_all(&uploads).unwrap();
        let missing = uploads.join("new.txt");
        let roots = vec![dir.path().to_string_lossy().to_string()];
        assert!(ensure_path_in_roots(Path::new(&missing), &roots, false).is_ok());
    }

    #[test]
    fn test_ensure_path_in_roots_missing_escape_rejected_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = dir.path().join("uploads");
        create_dir_all(&uploads).unwrap();
        let escaped = uploads.join("..").join("..").join("escape.txt");
        let roots = vec![dir.path().to_string_lossy().to_string()];
        let err = ensure_path_in_roots(Path::new(&escaped), &roots, false).unwrap_err();
        assert!(err.contains("not within any allowed root"), "got: {err}");
    }

    #[test]
    fn test_ensure_path_in_roots_broken_symlink_prefix_rejected_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let broken_target = dir.path().join("..").join("outside").join("missing-target");
        let link_path = dir.path().join("broken-link");
        std::os::unix::fs::symlink(&broken_target, &link_path).unwrap();
        let escaped = link_path.join("..").join("evil.txt");
        let roots = vec![dir.path().to_string_lossy().to_string()];
        let err = ensure_path_in_roots(Path::new(&escaped), &roots, false).unwrap_err();
        assert!(err.contains("cannot resolve path"), "got: {err}");
    }
}
