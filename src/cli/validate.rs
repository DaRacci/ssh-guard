use std::error::Error;

use crate::{
    config::{Config, action::Action},
    errors::GuardError,
};

pub(crate) fn validate(config_path: &str) -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_file(config_path)?;
    println!("Validating config: {config_path}");

    let mut errors: Vec<String> = Vec::new();

    for (i, rule) in cfg.rules.iter().enumerate() {
        if let Action::Run { binary, .. } = &rule.action {
            let path = std::path::Path::new(binary);
            if !path.exists() {
                errors.push(format!("rule[{i}]: binary '{binary}' does not exist"));
            } else if !rule.implicit_symlinks {
                match std::fs::symlink_metadata(binary) {
                    Ok(meta) if meta.file_type().is_symlink() => match path.canonicalize() {
                        Ok(resolved) => {
                            errors.push(format!(
                                    "rule[{i}]: binary '{binary}' is a symlink → '{}' (implicit_symlinks disabled). Set implicit_symlinks=true or use the real path.",
                                    resolved.display()
                                ));
                        }
                        Err(_) => {
                            errors.push(format!(
                                    "rule[{i}]: binary '{binary}' is a symlink and cannot be resolved (implicit_symlinks disabled)"
                                ));
                        }
                    },
                    Err(e) => {
                        errors.push(format!("rule[{i}]: cannot stat binary '{binary}': {e}"));
                    }
                    _ => {} // not a symlink, OK
                }
            }
        }
    }

    if errors.is_empty() {
        println!("Config is valid. {} rule(s) checked.", cfg.rules.len());
        Ok(())
    } else {
        for err in &errors {
            eprintln!("  - {err}");
        }
        let detail = errors.join("; ");
        Err(Box::new(GuardError::Validation(format!(
            "{} validation error(s): {}",
            errors.len(),
            detail
        ))))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::NamedTempFile;

    use super::validate;

    #[test]
    fn test_validate_valid_config_with_existing_binary() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "/usr/bin/env", args = [] }}
implicit_symlinks = true
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn test_validate_missing_binary() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "/nonexistent/path/xyz", args = [] }}
implicit_symlinks = true
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected Err");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "expected 'does not exist' in error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_symlink_with_implicit_disabled() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "/bin/sh", args = [] }}
implicit_symlinks = false
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);

        // /bin/sh is a symlink on NixOS — expect symlink error
        // On other systems it may be a real file; handle gracefully
        match result {
            Ok(()) => {
                // Not a symlink on this system — test passes vacuously
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("symlink"),
                    "expected 'symlink' in error, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_validate_multiple_rules_mixed() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "/usr/bin/env", args = [] }}
implicit_symlinks = true

[[rules]]
action = {{ type = "run", binary = "/does/not/exist", args = [] }}
implicit_symlinks = true
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected Err for invalid rule");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("1 validation error(s):") || msg.contains("1 validation error(s)"),
            "expected 1 error, got: {msg}"
        );
        assert!(
            msg.contains("does not exist"),
            "expected 'does not exist', got: {msg}"
        );
    }

    #[test]
    fn test_validate_no_run_actions() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "show_help" }}
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn test_validate_all_rule_types_mixed() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "/usr/bin/env", args = [] }}
implicit_symlinks = true

[[rules]]
action = {{ type = "read_file", path_capture = "{{file}}", root_set = "data" }}

[[rules]]
action = {{ type = "show_help" }}
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn test_validate_nonexistent_config_file() {
        let path = "/tmp/__ssh_guard_test_nonexistent_12345.toml";
        let result = validate(path);
        assert!(result.is_err(), "expected Err for missing file");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cannot read config file"),
            "expected 'cannot read config file', got: {msg}"
        );
    }

    /// Create a temp symlink targeting a real temp file, implicit_symlinks=false.
    /// This hits the symlink check path (L24-29: symlink resolved).
    #[test]
    fn test_validate_symlink_to_real_target_implicit_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("real_binary");
        std::fs::write(&target_path, "#!/bin/sh\necho hi").unwrap();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let link_path = dir.path().join("symlink_binary");
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        let config_path = dir.path().join("config.toml");
        let toml = format!(
            r#"
[[rules]]
action = {{ type = "run", binary = "{link}", args = [] }}
implicit_symlinks = false
"#,
            link = link_path.display()
        );
        std::fs::write(&config_path, &toml).unwrap();

        let result = validate(config_path.to_str().unwrap());
        assert!(
            result.is_err(),
            "expected Err for symlink with implicit_symlinks=false"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("symlink"),
            "expected 'symlink' in error, got: {err}"
        );
        assert!(
            err.contains("implicit_symlinks"),
            "expected 'implicit_symlinks' in error, got: {err}"
        );
    }

    /// Dangling symlink with implicit_symlinks=false.
    /// The symlink exists on disk but points to nothing.
    /// `exists()` follows the symlink → target missing → "does not exist" error
    /// (not the symlink check path, since exists() returns false first).
    #[test]
    fn test_validate_dangling_symlink_implicit_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let link_path = dir.path().join("dangling_binary");
        std::os::unix::fs::symlink("/nonexistent/target/12345", &link_path).unwrap();

        let config_path = dir.path().join("config.toml");
        let toml = format!(
            r#"
[[rules]]
action = {{ type = "run", binary = "{link}", args = [] }}
implicit_symlinks = false
"#,
            link = link_path.display()
        );
        std::fs::write(&config_path, &toml).unwrap();

        let result = validate(config_path.to_str().unwrap());
        assert!(result.is_err(), "expected Err for dangling symlink");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not exist"),
            "expected 'does not exist' for dangling symlink, got: {err}"
        );
    }

    /// Symlink with implicit_symlinks=true → should pass validation.
    #[test]
    fn test_validate_symlink_with_implicit_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("real_binary");
        std::fs::write(&target_path, "#!/bin/sh\necho hi").unwrap();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let link_path = dir.path().join("symlink_binary");
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        let config_path = dir.path().join("config.toml");
        let toml = format!(
            r#"
[[rules]]
action = {{ type = "run", binary = "{link}", args = [] }}
implicit_symlinks = true
"#,
            link = link_path.display()
        );
        std::fs::write(&config_path, &toml).unwrap();

        let result = validate(config_path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "expected Ok for symlink with implicit_symlinks=true, got: {result:?}"
        );
    }

    /// Deep symlink chain — 38 symlinks pointing to the next, ends at a real file.
    /// Under MAXSYMLINKS (40), so both stat() and realpath() succeed.
    /// Validation should fail: it's a symlink with implicit_symlinks=false.
    #[test]
    fn test_validate_deep_symlink_chain() {
        let dir = tempfile::tempdir().unwrap();

        // Create a real target file
        let target_path = dir.path().join("level_40");
        std::fs::write(&target_path, "#!/bin/sh\necho hi").unwrap();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Create a chain of 38 symlinks: level_0 -> level_1 -> ... -> level_38 -> level_40
        // 38 symlinks + 1 resolution for the final target = 39 symlink traversals
        // Under MAXSYMLINKS (40), so stat() and realpath() should both succeed.
        let max_links = 38usize;
        for i in (0..max_links).rev() {
            let prev = if i == max_links - 1 {
                target_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            } else {
                format!("level_{}", i + 1)
            };
            let link = dir.path().join(format!("level_{i}"));
            std::os::unix::fs::symlink(&prev, &link).unwrap();
        }

        let first_link = dir.path().join("level_0");
        let config_path = dir.path().join("config.toml");
        let toml = format!(
            r#"
[[rules]]
action = {{ type = "run", binary = "{link}", args = [] }}
implicit_symlinks = false
"#,
            link = first_link.display()
        );
        std::fs::write(&config_path, &toml).unwrap();

        let result = validate(config_path.to_str().unwrap());
        // On Linux, stat() follows up to MAXSYMLINKS (40) symlinks.
        // With 38 links + target, both stat() and realpath() should succeed.
        // The symlink IS a symlink, so validation fails with symlink error.
        assert!(result.is_err(), "expected Err for symlink chain");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("symlink"),
            "expected 'symlink' in symlink chain error, got: {err}"
        );
        assert!(
            err.contains("implicit_symlinks"),
            "expected 'implicit_symlinks' in error, got: {err}"
        );
    }

    /// The `symlink_metadata` Err branch (L125-127) at the end of validate()
    /// is triggered when `path.exists()` returns true but `symlink_metadata()`
    /// fails on that same path. This is a TOCTOU race condition in practice —
    /// it requires the file to be deleted, permissions revoked, or filesystem
    /// error to occur between the two calls. Not reliably testable without
    /// race conditions or kernel-level fault injection.
    ///
    /// Similarly, the `canonicalize` Err branch (L31-37) inside the symlink
    /// check is reached when `path.exists()` and `symlink_metadata()` both
    /// succeed (symlink exists, target exists), but `canonicalize()` fails.
    /// This also requires a TOCTOU race or a path resolution difference
    /// between stat() and realpath(), which is kernel-dependent.
    ///
    /// These branches exist for correctness in edge-case failure scenarios.

    #[test]
    fn test_validate_empty_rules() {
        // rules field has #[serde(default)] — omitting it parses as empty vec
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[global]
audit_log = "/dev/null"
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }
}
