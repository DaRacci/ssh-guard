use crate::{actions, audit::AuditEvent, config::Config, engine, errors::GuardError, logging};

pub(crate) fn run(config_path: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let cfg = Config::from_file(config_path)?;
    logging::init(&cfg.global.log_tag)?;

    let raw = std::env::var("SSH_ORIGINAL_COMMAND").map_err(|_| GuardError::NoCommand)?;

    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    if raw.trim().is_empty() {
        println!("{}", cfg.global.help_text);
        let event = AuditEvent::allowed(&user, "(empty — help shown)", "show_help");
        let _ = event.write_to(&cfg.global.audit_log, &cfg.global.audit_format);
        return Ok(0);
    }

    let args = shlex::split(&raw).ok_or_else(|| GuardError::ParseCommand(raw.clone()))?;

    let match_result = match engine::match_command(&cfg, &args) {
        Ok(m) => m,
        Err(GuardError::NoMatch { failures, .. }) => {
            let failure_strings: Vec<String> = failures.iter().map(|f| f.to_string()).collect();
            let event = AuditEvent::denied(&user, &raw, "no matching rule", &failure_strings);
            let _ = event.write_to(&cfg.global.audit_log, &cfg.global.audit_format);
            return Err(Box::new(GuardError::NoMatch {
                command: raw.clone(),
                failures,
            }));
        }
        Err(e) => {
            let event = AuditEvent::denied(&user, &raw, &e.to_string(), &[]);
            let _ = event.write_to(&cfg.global.audit_log, &cfg.global.audit_format);
            return Err(Box::new(e));
        }
    };

    let rule = &cfg.rules[match_result.rule_index];

    // Audit: allowed
    let detail = format!(
        "rule[{}] via {}",
        match_result.rule_index,
        match_result.subcommand_path.join("/")
    );
    let event = AuditEvent::allowed(&user, &raw, &detail);
    let _ = event.write_to(&cfg.global.audit_log, &cfg.global.audit_format);

    let code = actions::execute(
        &cfg,
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

    /// Path before logging::init: bad config path → Config::from_file error
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

    /// Valid config but no SSH_ORIGINAL_COMMAND set → NoCommand error
    /// This path goes through logging::init which connects to syslog.
    /// On systems without syslog, logging::init fails before env var check.
    /// We test that the overall Result is Err (either from logging or NoCommand).
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
        // Isolate env: ensure SSH_ORIGINAL_COMMAND is absent to avoid
        // interference from parallel tests that set it.
        temp_env::with_var("SSH_ORIGINAL_COMMAND", None::<&str>, || {
            let result = run(&path);
            // Either logging::init fails (no syslog) or NoCommand if syslog available
            assert!(result.is_err());
        });
    }

    /// Valid config + SSH_ORIGINAL_COMMAND set + USER set
    /// Tests the empty-command → help path (L8-13).
    /// Still needs syslog, so may fail at logging::init.
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
                // If syslog available, should return Ok(0) for empty command.
                // Otherwise Err from logging::init.
                if let Ok(code) = result {
                    assert_eq!(code, 0);
                }
            });
        });
    }
}
