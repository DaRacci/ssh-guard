use crate::{actions, config::Config, engine, errors::GuardError, logging, middleware};

fn current_user() -> String {
    current_os_user()
        .or_else(|| std::env::var("USER").ok().filter(|user| !user.is_empty()))
        .unwrap_or_else(|| "unknown".into())
}

fn current_os_user() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let effective_uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse::<u32>()
        .ok()?;

    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let username = fields.next()?;
            let _password = fields.next()?;
            let uid = fields.next()?.parse::<u32>().ok()?;
            (uid == effective_uid).then(|| username.to_string())
        })
}

pub(crate) fn run(config_path: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let cfg = Config::from_file(config_path)?;
    let config_hash = Config::sha256(config_path)?;
    let session_id = crate::audit::new_session_id();
    let user = current_user();

    let effective = cfg.resolve_for_user(&user)?;
    let effective_global = effective.global.clone();

    logging::init(&effective_global.log_tag)?;

    let raw = std::env::var("SSH_ORIGINAL_COMMAND").map_err(|_| GuardError::NoCommand)?;

    let chain = middleware::default_chain(&effective_global);

    if raw.trim().is_empty() {
        println!("{}", effective_global.help_text);
        let session = middleware::Session {
            user: &user,
            command: "(empty - help shown)",
            session_id: &session_id,
            config_hash: &config_hash,
        };
        chain.on_outcome(
            &session,
            &middleware::Outcome::Allowed {
                exit_code: 0,
                detail: "show_help",
            },
        );
        return Ok(0);
    }

    let args = shlex::split(&raw).ok_or_else(|| GuardError::ParseCommand(raw.clone()))?;

    let session = middleware::Session {
        user: &user,
        command: &raw,
        session_id: &session_id,
        config_hash: &config_hash,
    };

    let deny = |reason: &str, failures: &[String]| {
        chain.on_outcome(&session, &middleware::Outcome::Denied { reason, failures });
    };

    let match_result = match engine::match_command(&effective, &args) {
        Ok(m) => m,
        Err(GuardError::NoMatch { failures, .. }) => {
            let failure_strings: Vec<String> = failures
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            deny("no matching rule", &failure_strings);
            return Err(Box::new(GuardError::NoMatch {
                command: raw.clone(),
                failures,
            }));
        }
        Err(e) => {
            deny(&e.to_string(), &[]);
            return Err(Box::new(e));
        }
    };

    let rule = &effective.rules[match_result.rule_index];

    let detail = format!(
        "rule[{}] via {}",
        match_result.rule_index,
        match_result.subcommand_path.join("/")
    );

    let info = middleware::MatchInfo {
        rule_index: match_result.rule_index,
        subcommand_path: &match_result.subcommand_path,
        detail: &detail,
    };
    if let middleware::Decision::Deny(reason) = chain.on_match(&session, &info) {
        deny(&reason, &[]);
        return Err(Box::new(GuardError::Denied(reason)));
    }

    let code = match actions::execute(
        &effective,
        rule,
        &match_result.subcommand_path,
        &match_result.captures,
        &args,
    ) {
        Ok(code) => code,
        Err(e) => {
            deny(&e.to_string(), &[]);
            return Err(Box::new(e));
        }
    };

    chain.on_outcome(
        &session,
        &middleware::Outcome::Allowed {
            exit_code: code,
            detail: &detail,
        },
    );
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::run;
    use std::io::Write;

    /// Write a config with a single `run` rule whose `command` is `true` and
    /// whose action executes the current test binary's `subprocess_helper_success`
    /// test (exit 0). Audit output is JSON to `audit_path`.
    fn write_run_rule_config(audit_path: &str) -> tempfile::NamedTempFile {
        let binary = std::env::current_exe().unwrap();
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[global]
audit_log = "{audit_path}"
audit_format = "json"
log_tag = "ssh-guard-test"
help_text = "test help"

[[rules]]
command = "true"

[rules.action]
type = "run"
binary = "{binary}"
args = ["--exact", "kinds::run::tests::subprocess_helper_success"]
"#,
            binary = binary.to_str().unwrap()
        )
        .unwrap();
        cfg
    }

    fn write_show_help_config(audit_path: &str) -> tempfile::NamedTempFile {
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[global]
audit_log = "{audit_path}"
audit_format = "json"
log_tag = "ssh-guard-test"
help_text = "test help shown"

[[rules]]
action = {{ type = "show_help" }}
"#
        )
        .unwrap();
        cfg
    }

    #[test]
    fn test_run_writes_started_then_allowed() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_run_rule_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("USER", Some("testuser"), || {
            temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("true"), || {
                let code = run(&path).unwrap();
                assert_eq!(code, 0);
            });
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 2, "audit: {contents}");
        let mut lines = contents.lines();
        assert!(
            lines.next().unwrap().contains("\"started\""),
            "first event must be started: {contents}"
        );
        assert!(
            lines.next().unwrap().contains("\"allowed\""),
            "second event must be allowed: {contents}"
        );
    }

    #[test]
    fn test_run_writes_denied_on_no_match() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_run_rule_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("USER", Some("testuser"), || {
            temp_env::with_var(
                "SSH_ORIGINAL_COMMAND",
                Some("definitely-not-a-command"),
                || {
                    assert!(run(&path).is_err());
                },
            );
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"denied\""), "audit: {contents}");
    }

    #[test]
    fn test_run_empty_command_writes_single_allowed_no_started() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_show_help_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("USER", Some("testuser"), || {
            temp_env::with_var("SSH_ORIGINAL_COMMAND", Some(""), || {
                let code = run(&path).unwrap();
                assert_eq!(code, 0);
            });
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"allowed\""), "audit: {contents}");
        assert!(
            !contents.contains("\"started\""),
            "empty-command path must not emit started: {contents}"
        );
        assert!(
            contents.contains("(empty - help shown)"),
            "command field must be preserved as `(empty - help shown)`: {contents}"
        );
    }

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
