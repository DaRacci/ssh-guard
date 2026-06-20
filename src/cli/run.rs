use crate::{actions, audit::AuditEvent, config::Config, engine, errors::GuardError, logging};

pub(crate) fn run(config_path: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let cfg = Config::from_file(config_path)?;
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    let effective = cfg.resolve_for_user(&user)?;
    let effective_global = effective.global.clone();

    logging::init(&effective_global.log_tag)?;

    let raw = std::env::var("SSH_ORIGINAL_COMMAND").map_err(|_| GuardError::NoCommand)?;

    if raw.trim().is_empty() {
        println!("{}", effective_global.help_text);
        let event = AuditEvent::allowed(&user, "(empty - help shown)", "show_help");
        let _ = event.write_to(&effective_global.audit_log, &effective_global.audit_format);
        return Ok(0);
    }

    let args = shlex::split(&raw).ok_or_else(|| GuardError::ParseCommand(raw.clone()))?;

    let match_result = match engine::match_command(&effective, &args) {
        Ok(m) => m,
        Err(GuardError::NoMatch { failures, .. }) => {
            let failure_strings: Vec<String> = failures.iter().map(|f| f.to_string()).collect();
            let event = AuditEvent::denied(&user, &raw, "no matching rule", &failure_strings);
            let _ = event.write_to(&effective_global.audit_log, &effective_global.audit_format);
            return Err(Box::new(GuardError::NoMatch {
                command: raw.clone(),
                failures,
            }));
        }
        Err(e) => {
            let event = AuditEvent::denied(&user, &raw, &e.to_string(), &[]);
            let _ = event.write_to(&effective_global.audit_log, &effective_global.audit_format);
            return Err(Box::new(e));
        }
    };

    let rule = &effective.rules[match_result.rule_index];

    let detail = format!(
        "rule[{}] via {}",
        match_result.rule_index,
        match_result.subcommand_path.join("/")
    );
    let event = AuditEvent::allowed(&user, &raw, &detail);
    let _ = event.write_to(&effective_global.audit_log, &effective_global.audit_format);

    let code = actions::execute(
        &effective,
        rule,
        &match_result.subcommand_path,
        &match_result.captures,
        &args,
    )?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::run;
    use std::io::Write;

    #[test]
    fn test_run_bad_config_path() {
        let result = run("/tmp/nonexistent-ssh-guard-config-12345.toml");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot read config file"),
            "expected config error, got: {err}"
        );
    }

    #[test]
    fn test_run_valid_config_no_env() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[global]
audit_log = "/dev/null"
log_tag = "ssh-guard-test"
help_text = "test help"

[[rules]]
action = {{ type = "show_help" }}
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        temp_env::with_var("SSH_ORIGINAL_COMMAND", None::<&str>, || {
            let result = run(&path);
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_run_with_env_empty_command() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[global]
audit_log = "/dev/null"
log_tag = "ssh-guard-test"
help_text = "test help shown"

[[rules]]
action = {{ type = "show_help" }}
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        temp_env::with_var("USER", Some("testuser"), || {
            temp_env::with_var("SSH_ORIGINAL_COMMAND", Some(""), || {
                let result = run(&path);
                if let Ok(code) = result {
                    assert_eq!(code, 0);
                }
            });
        });
    }

    #[test]
    fn test_run_with_profile_matching_help() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
[global]
audit_log = "/dev/null"
log_tag = "ssh-guard-test"
help_text = "base help"

[[rules]]
action = {{ type = "show_help" }}

[profiles.admin]
users = ["admin_user"]

[profiles.admin.global]
help_text = "admin help"
"#
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        temp_env::with_var("USER", Some("admin_user"), || {
            temp_env::with_var("SSH_ORIGINAL_COMMAND", Some(""), || {
                let result = run(&path);
                if let Ok(code) = result {
                    assert_eq!(code, 0);
                }
            });
        });
    }
}
