use log::LevelFilter;

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
        let result = init("ssh-guard-test");
        match result {
            Ok(()) => {}
            Err(_) => {}
        }
    }
}
