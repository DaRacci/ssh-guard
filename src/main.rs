#![forbid(unsafe_code)]

use std::process;

use ssh_guard::cli;

fn main() {
    let result = cli::run();
    match result {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("ssh-guard: {e}");
            let formatter = syslog::Formatter3164 {
                facility: syslog::Facility::LOG_AUTH,
                hostname: None,
                process: "ssh-guard".to_string(),
                pid: process::id(),
            };
            if let Ok(logger) = syslog::unix(formatter) {
                let _ = log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                    .map(|()| log::set_max_level(log::LevelFilter::Info));
                let _ = log::error!("ssh-guard error: {e}");
            }
            process::exit(1);
        }
    }
}
