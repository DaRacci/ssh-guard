use log::LevelFilter;

pub fn init(tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_AUTH,
        hostname: None,
        process: tag.to_string(),
        pid: std::process::id(),
    };

    // Prefer the local syslog socket, but do not treat its absence as fatal.
    // sshd ForceCommand environments always have /dev/log, yet containers and
    // test harnesses may not. Fall back to stderr so the guard stays usable
    // and observable wherever it runs.
    match syslog::unix(formatter.clone()) {
        Ok(logger) => {
            log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                .map(|()| log::set_max_level(LevelFilter::Info))?;
        }
        Err(syslog_err) => {
            let logger = StderrLogger {
                tag: tag.to_string(),
            };
            log::set_boxed_logger(Box::new(logger))
                .map(|()| log::set_max_level(LevelFilter::Info))?;
            eprintln!("ssh-guard: syslog unavailable ({syslog_err}); logging to stderr");
        }
    }

    Ok(())
}

/// Minimal `log::Log` sink writing to stderr. Fallback when no syslog
/// socket is reachable.
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
        let result = init("ssh-guard-test");
        match result {
            Ok(()) => {}
            Err(_) => {}
        }
    }
}
