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
