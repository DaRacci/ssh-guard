use crate::{
    actions,
    config::Config,
    engine,
    errors::GuardError,
    logging,
    middleware::{self, Decision},
};

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
    run_with_chain(config_path, None)
}

/// `None` uses the default chain.
fn run_with_chain(
    config_path: &str,
    chain_override: Option<middleware::Chain>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let cfg = Config::from_file(config_path)?;
    let config_hash = Config::sha256(config_path)?;
    let session_id = crate::audit::new_session_id();
    let user = current_user();

    let effective = cfg.resolve_for_user(&user)?;
    logging::init(&effective.global.log_tag)?;

    // An unset variable means sshd did not invoke us as a forced command;
    // there is no request to match or audit.
    let raw = std::env::var("SSH_ORIGINAL_COMMAND").map_err(|_| GuardError::NoCommand)?;
    let chain = chain_override.unwrap_or_else(|| middleware::default_chain(&effective));
    let session = middleware::Session {
        user: &user,
        command: &raw,
        session_id: &session_id,
        config_hash: &config_hash,
    };

    let deny = |reason: &str, failures: &[String]| {
        chain.on_outcome(&session, &middleware::Outcome::Denied { reason, failures });
    };

    // A middleware may veto the request or handle it outright.
    match chain.on_request(&session) {
        Decision::Deny(reason) => {
            deny(&reason, &[]);
            return Err(Box::new(GuardError::Denied(reason)));
        }
        Decision::Handled { exit_code, detail } => {
            chain.on_outcome(
                &session,
                &middleware::Outcome::Allowed { exit_code, detail },
            );
            return Ok(exit_code);
        }
        Decision::Continue => {}
    }

    // A command that cannot be parsed is a denial, not a silent error: record
    // it through the same outcome path as a match failure.
    let Some(args) = shlex::split(&raw) else {
        let reason = GuardError::ParseCommand(raw.clone()).to_string();
        deny(&reason, &[]);
        return Err(Box::new(GuardError::ParseCommand(raw)));
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

    match chain.on_match(&session, &info) {
        Decision::Continue => {}
        Decision::Deny(reason) => {
            deny(&reason, &[]);
            return Err(Box::new(GuardError::Denied(reason)));
        }
        Decision::Handled { exit_code, detail } => {
            chain.on_outcome(
                &session,
                &middleware::Outcome::Allowed { exit_code, detail },
            );
            return Ok(exit_code);
        }
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
#[coverage(off)]
mod tests {
    use super::{current_user, run, run_with_chain};
    use crate::config::audit::AuditFormat;
    use crate::middleware;
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

    /// A config with `dry_run = true` and a `run` rule whose binary does not
    /// exist: a dry run must skip execution rather than fail to spawn.
    fn write_dry_run_config(audit_path: &str) -> tempfile::NamedTempFile {
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[global]
audit_log = "{audit_path}"
audit_format = "json"
log_tag = "ssh-guard-test"
help_text = "help"
dry_run = true

[[rules]]
command = "true"

[rules.action]
type = "run"
binary = "/nonexistent/dry-run-binary"
"#
        )
        .unwrap();
        cfg
    }

    fn write_help_config(audit_path: &str) -> tempfile::NamedTempFile {
        let mut cfg = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[global]
audit_log = "{audit_path}"
audit_format = "json"
log_tag = "ssh-guard-test"
help_text = "test help shown"
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

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("true"), || {
            let code = run(&path).unwrap();
            assert_eq!(code, 0);
        });

        // `current_user()` resolves the OS user (not the `USER` env var), so
        // assert the resolved value is plumbed through rather than setting an
        // ineffective `USER`.
        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 2, "audit: {contents}");
        assert!(
            contents.contains(&format!("\"user\":\"{}\"", current_user())),
            "audit must carry the resolved user: {contents}"
        );
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

    struct DenyOnRequest;

    impl middleware::Middleware for DenyOnRequest {
        fn name(&self) -> &'static str {
            "deny_on_request"
        }

        fn on_request(&self, _s: &middleware::Session<'_>) -> middleware::Decision {
            middleware::Decision::Deny("blocked".into())
        }

        fn on_outcome(&self, _s: &middleware::Session<'_>, _o: &middleware::Outcome<'_>) {}
    }

    #[test]
    fn test_run_denies_on_request_veto() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_run_rule_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        let chain = middleware::Chain::new(vec![
            Box::new(middleware::audit::Audit {
                log: audit_path.clone(),
                format: AuditFormat::Json,
            }),
            Box::new(DenyOnRequest),
        ]);

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("true"), || {
            let err = run_with_chain(&path, Some(chain))
                .expect_err("on_request veto must deny")
                .to_string();
            assert!(err.contains("command denied: blocked"), "got: {err}");
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"denied\""), "audit: {contents}");
        assert!(
            !contents.contains("\"started\""),
            "on_request veto precedes matching, so no started event: {contents}"
        );
    }

    #[test]
    fn test_run_writes_denied_on_no_match() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_run_rule_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var(
            "SSH_ORIGINAL_COMMAND",
            Some("definitely-not-a-command"),
            || {
                assert!(run(&path).is_err());
            },
        );

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"denied\""), "audit: {contents}");
        assert!(
            contents.contains(&format!("\"user\":\"{}\"", current_user())),
            "audit must carry the resolved user: {contents}"
        );
    }

    #[test]
    fn test_run_audits_parse_failure() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_run_rule_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("true 'unterminated"), || {
            let err = run(&path).expect_err("malformed command must fail");
            assert!(err.to_string().contains("invalid command"), "got: {err}");
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"denied\""), "audit: {contents}");
        assert!(
            !contents.contains("\"started\""),
            "parse failure must not emit started: {contents}"
        );
    }

    #[test]
    fn test_run_empty_command_writes_single_allowed_no_started() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_help_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some(""), || {
            let code = run(&path).unwrap();
            assert_eq!(code, 0);
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
        assert!(
            contents.contains(&format!("\"user\":\"{}\"", current_user())),
            "audit must carry the resolved user: {contents}"
        );
    }

    #[test]
    fn test_run_raw_help_writes_single_allowed_no_started() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_help_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("help"), || {
            let code = run(&path).unwrap();
            assert_eq!(code, 0);
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"allowed\""), "audit: {contents}");
        assert!(
            !contents.contains("\"started\""),
            "raw-help path must not emit started: {contents}"
        );
    }

    #[test]
    fn test_run_dry_run_skips_execution() {
        let audit = tempfile::NamedTempFile::new().unwrap();
        let audit_path = audit.path().to_str().unwrap().to_string();
        let cfg = write_dry_run_config(&audit_path);
        let path = cfg.path().to_str().unwrap().to_string();

        temp_env::with_var("SSH_ORIGINAL_COMMAND", Some("true"), || {
            let code = run(&path).expect("dry run must not attempt execution");
            assert_eq!(code, 0);
        });

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(contents.lines().count(), 1, "audit: {contents}");
        assert!(contents.contains("\"allowed\""), "audit: {contents}");
        assert!(contents.contains("\"dry_run\""), "audit: {contents}");
        assert!(
            !contents.contains("\"started\""),
            "dry run must not emit started: {contents}"
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
