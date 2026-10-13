use log::LevelFilter;

/// Initialize syslog-backed logging for `ssh-guard`.
///
/// Idempotent: the process-global logger can only be installed once.
/// This keeps `run` usable both from the CLI and from tests.
///
/// # Errors
///
/// Currently never fails; the `Result` is retained for call-site stability.
/// Syslog being unreachable is handled by falling back to stderr, not by error.
pub fn init(tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_AUTH,
        hostname: None,
        process: tag.to_string(),
        pid: std::process::id(),
    };

    // Prefer the local syslog socket, but do not treat its absence as fatal.
    // sshd ForceCommand environments always have /dev/log, yet containers and test harnesses may not.
    // Fall back to stderr so the guard stays usable and observable wherever it runs.
    match syslog::unix(formatter.clone()) {
        Ok(logger) => {
            // A pre-existing logger, leave it alone.
            let _ = log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)));
        }
        Err(syslog_err) => {
            let logger = StderrLogger {
                tag: tag.to_string(),
            };
            if log::set_boxed_logger(Box::new(logger)).is_ok() {
                eprintln!("ssh-guard: syslog unavailable ({syslog_err}); logging to stderr");
            }
        }
    }

    log::set_max_level(LevelFilter::Info);
    Ok(())
}

/// Minimal `log::Log` sink writing to stderr.
/// Fallback when no syslog socket is reachable.
struct StderrLogger {
    tag: String,
}

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "{}[{}]: {}: {}",
                self.tag,
                std::process::id(),
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
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
