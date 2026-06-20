pub mod merge;
pub mod run;
pub mod validate;

use clap::Parser;

#[derive(Parser)]
#[command(name = "ssh-guard")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Run the SSH guard (reads SSH_ORIGINAL_COMMAND)
    Run {
        #[arg(long)]
        config: String,
    },

    /// Add or merge a command rule into the config
    AddRule {
        #[arg(long)]
        config: String,
        /// The command to add, e.g. "journalctl --since yesterday -n 10"
        #[arg(long)]
        cmd: String,
        /// Target profile name. If omitted, modifies base config.
        #[arg(long)]
        profile: Option<String>,
    },

    /// Validate the config (checks binary paths, symlinks, syntax)
    Validate {
        #[arg(long)]
        config: String,
    },
}

pub fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Run { config } => run::run(config),
        Command::AddRule {
            config,
            cmd,
            profile,
        } => merge::add_rule(config, cmd, profile.as_deref())
            .map(|_| 0)
            .map_err(|e| e.into()),
        Command::Validate { config } => validate::validate(config).map(|_| 0).map_err(|e| e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_run() {
        let cli =
            Cli::try_parse_from(&["ssh-guard", "run", "--config", "/tmp/test-ssh-guard.toml"])
                .unwrap();
        match &cli.command {
            Command::Run { config } => {
                assert_eq!(config, "/tmp/test-ssh-guard.toml");
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn test_cli_parse_add_rule() {
        let cli = Cli::try_parse_from(&[
            "ssh-guard",
            "add-rule",
            "--config",
            "/tmp/test-ssh-guard.toml",
            "--cmd",
            "journalctl -n 10",
        ])
        .unwrap();
        match &cli.command {
            Command::AddRule {
                config,
                cmd,
                profile,
            } => {
                assert_eq!(config, "/tmp/test-ssh-guard.toml");
                assert_eq!(cmd, "journalctl -n 10");
                assert!(profile.is_none());
            }
            _ => panic!("expected AddRule command"),
        }
    }

    #[test]
    fn test_cli_parse_add_rule_with_profile() {
        let cli = Cli::try_parse_from(&[
            "ssh-guard",
            "add-rule",
            "--config",
            "/tmp/test-ssh-guard.toml",
            "--cmd",
            "journalctl -n 10",
            "--profile",
            "admin",
        ])
        .unwrap();
        match &cli.command {
            Command::AddRule {
                config,
                cmd,
                profile,
            } => {
                assert_eq!(config, "/tmp/test-ssh-guard.toml");
                assert_eq!(cmd, "journalctl -n 10");
                assert_eq!(profile.as_deref(), Some("admin"));
            }
            _ => panic!("expected AddRule command"),
        }
    }

    #[test]
    fn test_cli_parse_validate() {
        let cli = Cli::try_parse_from(&[
            "ssh-guard",
            "validate",
            "--config",
            "/tmp/test-ssh-guard.toml",
        ])
        .unwrap();
        match &cli.command {
            Command::Validate { config } => {
                assert_eq!(config, "/tmp/test-ssh-guard.toml");
            }
            _ => panic!("expected Validate command"),
        }
    }

    #[test]
    fn test_cli_parse_requires_config() {
        // Run without --config should fail
        let result = Cli::try_parse_from(&["ssh-guard", "run"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_run_dispatch_errors_on_bad_config() {
        let cmd = Command::Run {
            config: "/tmp/nonexistent-ssh-guard-config.toml".to_string(),
        };
        let result = match &cmd {
            Command::Run { config } => run::run(config),
            _ => unreachable!(),
        };
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot read config file"),
            "expected config error, got: {err}"
        );
    }

    #[test]
    fn test_cli_add_rule_dispatch_errors_on_bad_config() {
        let cmd = Command::AddRule {
            config: "/tmp/nonexistent-ssh-guard-config.toml".to_string(),
            cmd: "ls".to_string(),
            profile: None,
        };
        let result: Result<i32, Box<dyn std::error::Error>> = match &cmd {
            Command::AddRule {
                config,
                cmd,
                profile,
            } => merge::add_rule(config, cmd, profile.as_deref())
                .map(|_| 0)
                .map_err(|e| e.into()),
            _ => unreachable!(),
        };
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot read config file"),
            "expected config error, got: {err}"
        );
    }

    #[test]
    fn test_cli_validate_dispatch_errors_on_bad_config() {
        let cmd = Command::Validate {
            config: "/tmp/nonexistent-ssh-guard-config.toml".to_string(),
        };
        let result: Result<i32, Box<dyn std::error::Error>> = match &cmd {
            Command::Validate { config } => {
                validate::validate(config).map(|_| 0).map_err(|e| e.into())
            }
            _ => unreachable!(),
        };
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot read config file"),
            "expected config error, got: {err}"
        );
    }
}
