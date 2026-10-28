use std::error::Error;

use crate::{
    config::{Config, rule::Rule},
    errors::GuardError,
};

pub(crate) fn validate(config_path: &str) -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_file(config_path)?;
    println!("Validating config: {config_path}");

    let mut errors = cfg.validation_errors();
    validate_rules_env(&cfg.rules, "base", &mut errors);

    for (pname, profile) in &cfg.profiles {
        if let Some(ref rules) = profile.rules {
            validate_rules_env(rules, &format!("profile '{pname}'"), &mut errors);
        }
    }

    if errors.is_empty() {
        let count = cfg.rules.len();
        let profile_count = cfg
            .profiles
            .values()
            .filter_map(|p| p.rules.as_ref().map(std::vec::Vec::len))
            .sum::<usize>();
        let total = count + profile_count;
        println!(
            "Config is valid. {count} base rule(s), {profile_count} profile rule(s) ({total} total)."
        );
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

fn validate_rules_env(rules: &[Rule], scope: &str, errors: &mut Vec<String>) {
    for (index, rule) in rules.iter().enumerate() {
        let ctx = crate::kinds::EnvCtx { rule, scope, index };
        crate::kinds::kind_for(&rule.action).validate_env(&ctx, errors);
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tempfile::NamedTempFile;

    use super::validate;

    fn write_executable(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn test_validate_valid_config_with_existing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write_executable(&dir, "valid-binary");
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = true
"#,
            binary.display()
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
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
    fn test_validate_rejects_relative_existing_binary() {
        let binary = tempfile::Builder::new()
            .prefix("relative-binary-")
            .tempfile_in(".")
            .unwrap();
        std::fs::set_permissions(binary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let relative_path = binary.path().file_name().unwrap().to_str().unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{relative_path}", args = [] }}
implicit_symlinks = true
"#
        )
        .unwrap();

        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected Err");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("must be an absolute path"), "got: {msg}");
    }

    #[test]
    fn test_validate_symlink_with_implicit_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_executable(&dir, "real-binary");
        let link = dir.path().join("linked-binary");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = false
"#,
            link.display()
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected symlink validation error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("symlink"),
            "expected 'symlink' in error, got: {msg}"
        );
    }

    #[test]
    fn test_validate_multiple_rules_mixed() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write_executable(&dir, "valid-binary");
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = true

[[rules]]
action = {{ type = "run", binary = "/does/not/exist", args = [] }}
implicit_symlinks = true
"#,
            binary.display()
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
command = "help"
action = {{ type = "noop" }}
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_all_rule_types_mixed() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write_executable(&dir, "valid-binary");
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = true

[[rules]]
command = "cat"
action = {{ type = "read_file", path_capture = "{{file}}", root_set = "roots" }}
args = ["{{file:string}}"]
"#,
            binary.display()
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_rejects_unmatched_path_capture() {
        let mut tmp = NamedTempFile::new().unwrap();
        let value = toml::toml! {
            [[rules]]
            action = { type = "read_file", path_capture = "{string}", root_set = "roots" }
            command = "cat"
            args = ["{string}"]
        };
        let content = toml::to_string_pretty(&value).unwrap();
        write!(tmp, "{content}").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected Err for unmatched path_capture");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("path_capture") && msg.contains("{string}"),
            "expected error naming path_capture and '{{string}}', got: {msg}"
        );
    }

    #[test]
    fn test_validate_accepts_named_capture() {
        let mut tmp = NamedTempFile::new().unwrap();
        let value = toml::toml! {
            [[rules]]
            action = { type = "read_file", path_capture = "path", root_set = "roots" }
            command = "cat"
            args = ["{path:string}"]
        };
        let content = toml::to_string_pretty(&value).unwrap();
        write!(tmp, "{content}").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(
            result.is_ok(),
            "expected Ok for named capture, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_accepts_braced_capture_reference() {
        let mut tmp = NamedTempFile::new().unwrap();
        let value = toml::toml! {
            [[rules]]
            action = { type = "read_file", path_capture = "{path}", root_set = "roots" }
            command = "cat"
            args = ["{path:string}"]
        };
        let content = toml::to_string_pretty(&value).unwrap();
        write!(tmp, "{content}").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(
            result.is_ok(),
            "expected Ok for braced capture reference, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_rejects_unmatched_lines_capture() {
        let mut tmp = NamedTempFile::new().unwrap();
        let value = toml::toml! {
            [[rules]]
            action = { type = "tail_file", path_capture = "path", lines_capture = "n", root_set = "roots" }
            command = "tail"
            args = ["{path:string}"]
        };
        let content = toml::to_string_pretty(&value).unwrap();
        write!(tmp, "{content}").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err(), "expected Err for unmatched lines_capture");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("lines_capture"),
            "expected error naming lines_capture, got: {msg}"
        );
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

    /// Symlink to real target with `implicit_symlinks=false` should fail.
    #[test]
    fn test_validate_symlink_to_real_target_implicit_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("real_binary");
        std::fs::write(&target_path, "").unwrap();
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

    /// Dangling symlink: `exists()` returns false first → "does not exist" error.
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

    #[test]
    fn test_validate_env_rejects_dangling_symlink_via_registry() {
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
            "expected registry path to preserve 'does not exist', got: {err}"
        );
    }

    #[test]
    fn test_validate_symlink_with_implicit_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("real_binary");
        std::fs::write(&target_path, "").unwrap();
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

    /// 38-symlink chain under `MAXSYMLINKS` (40). Fails because `implicit_symlinks=false`.
    #[test]
    fn test_validate_deep_symlink_chain() {
        let dir = tempfile::tempdir().unwrap();

        let target_path = dir.path().join("level_40");
        std::fs::write(&target_path, "").unwrap();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o755)).unwrap();

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

    /// TOCTOU race-dependent branches (`symlink_metadata` and `canonicalize`)
    /// are not reliably testable without fault injection.

    #[test]
    fn test_validate_empty_rules() {
        // rules field has #[serde(default)], omitting it parses as empty vec
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
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_profile_rules_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write_executable(&dir, "valid-binary");
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = true

[profiles.admin]
users = ["admin_user"]

[[profiles.admin.rules]]
action = {{ type = "run", binary = "/nonexistent/profile/bin", args = [] }}
implicit_symlinks = true
"#,
            binary.display()
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("profile 'admin'"),
            "expected error mentioning profile 'admin', got: {err}"
        );
    }

    #[test]
    fn test_validate_duplicate_users() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[profiles.admin]
users = ["alice", "bob"]

[profiles.dev]
users = ["bob", "charlie"]
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duplicate user"),
            "expected 'duplicate user' error, got: {err}"
        );
    }

    #[test]
    fn test_validate_valid_profile_rules() {
        let dir = tempfile::tempdir().unwrap();
        let binary = write_executable(&dir, "valid-binary");
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[[rules]]
command = "help"
action = {{ type = "noop" }}

[profiles.admin]
users = ["admin_user"]

[[profiles.admin.rules]]
action = {{ type = "run", binary = "{}", args = [] }}
implicit_symlinks = true
"#,
            binary.display()
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let result = validate(&path);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }
}
