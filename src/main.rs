#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]
#![deny(clippy::pedantic)]
#![feature(coverage_attribute)]

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

#[cfg(test)]
#[coverage(off)]
mod tests {
    use clap::Parser;
    use ssh_guard::cli::Cli;

    #[test]
    fn cli_try_parse_validate() {
        let cli = Cli::try_parse_from(&["ssh-guard", "validate", "--config", "test.toml"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(
            cli.command,
            ssh_guard::cli::Command::Validate { .. }
        ));
    }

    #[test]
    fn cli_try_parse_run() {
        let cli = Cli::try_parse_from(&["ssh-guard", "run", "--config", "test.toml"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(cli.command, ssh_guard::cli::Command::Run { .. }));
    }

    #[test]
    fn cli_try_parse_add_rule() {
        let cli = Cli::try_parse_from(&[
            "ssh-guard",
            "add-rule",
            "--config",
            "test.toml",
            "--cmd",
            "systemctl status sshd",
        ]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(
            cli.command,
            ssh_guard::cli::Command::AddRule { .. }
        ));
    }
}
