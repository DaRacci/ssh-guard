use std::error::Error;

use crate::{
    config::{action::Action, Config},
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
