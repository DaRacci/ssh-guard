use log::LevelFilter;

/// Initialize syslog-backed logging for `ssh-guard`.
///
/// # Errors
///
/// Returns an error if syslog cannot be opened or global logger setup fails.
pub fn init(tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_AUTH,
        hostname: None,
        process: tag.to_string(),
        pid: std::process::id(),
    };

    let logger = syslog::unix(formatter)?;
    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Info))?;

    Ok(())
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;

    #[test]
    fn init_syslog() {
        let _ = init("ssh-guard-test");
    }
}
