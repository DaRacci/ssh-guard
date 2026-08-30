pub mod help;
pub mod merge;
pub mod run;
pub mod validate;

use clap::Parser;

/// Default config path used when neither `--config` nor the environment variable is provided.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/ssh_guard/config.toml";

/// Environment variable consulted when `--config` is not given.
pub const CONFIG_ENV_VAR: &str = "SSH_GUARD_CONFIG";

#[derive(Parser)]
#[command(name = "ssh-guard", disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Run the SSH guard (reads `SSH_ORIGINAL_COMMAND`)
    Run {
        #[arg(long)]
        config: Option<String>,
    },

    /// Add or merge a command rule into the config
    AddRule {
        #[arg(long)]
        config: Option<String>,
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
        config: Option<String>,
    },

    /// Render a usage listing derived from the config rules
    Help {
        #[arg(long)]
        config: String,
        /// Target profile name. If omitted, renders the base config.
        #[arg(long)]
        profile: Option<String>,
        /// Render subcommands as an indented tree instead of inline.
        #[arg(long)]
        tree: bool,
        /// Enrich template labels with contract details.
        #[arg(long)]
        verbose: bool,
        /// Colour output: auto, always, or never.
        #[arg(long, value_enum, default_value = "auto")]
        colour: help::ColourChoice,
    },
}

/// Resolve config path in order of precedence:
/// 1. `--config` argument
/// 2. `SSH_GUARD_CONFIG` environment variable
/// 3. default path `/etc/ssh_guard/config.toml`
#[must_use]
pub fn resolve_config_path(cli_config: &Option<String>) -> String {
    if let Some(path) = cli_config {
        return path.clone();
    }
    if let Ok(path) = std::env::var(CONFIG_ENV_VAR)
        && !path.is_empty()
    {
        return path;
    }
    DEFAULT_CONFIG_PATH.to_string()
}

/// Parse CLI args, dispatch subcommand, return process exit code.
///
/// # Errors
///
/// Returns error from subcommand execution, including config read/validation failures.
pub fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Run { config } => run::run(&resolve_config_path(config)),
        Command::AddRule {
            config,
            cmd,
            profile,
        } => merge::add_rule(&resolve_config_path(config), cmd, profile.as_deref())
            .map(|()| 0)
            .map_err(Into::into),
        Command::Validate { config } => {
            validate::validate(&resolve_config_path(config)).map(|()| 0)
        }
        Command::Help {
            config,
            profile,
            tree,
            verbose,
            colour,
        } => help::help(config, profile.as_deref(), *tree, *verbose, *colour),
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_borrows_for_generic_args,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_run() {
        let cli =
            Cli::try_parse_from(&["ssh-guard", "run", "--config", "/tmp/test-ssh-guard.toml"])
                .unwrap();
        match &cli.command {
            Command::Run { config } => {
                assert_eq!(config.as_deref(), Some("/tmp/test-ssh-guard.toml"));
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
                assert_eq!(config.as_deref(), Some("/tmp/test-ssh-guard.toml"));
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
                assert_eq!(config.as_deref(), Some("/tmp/test-ssh-guard.toml"));
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
                assert_eq!(config.as_deref(), Some("/tmp/test-ssh-guard.toml"));
            }
            _ => panic!("expected Validate command"),
        }
    }

    #[test]
    fn test_cli_parse_help() {
        let cli =
            Cli::try_parse_from(&["ssh-guard", "help", "--config", "/tmp/test.toml"]).unwrap();
        match &cli.command {
            Command::Help {
                config,
                profile,
                tree,
                verbose,
                colour,
            } => {
                assert_eq!(config, "/tmp/test.toml");
                assert!(profile.is_none());
                assert!(!tree);
                assert!(!verbose);
                assert!(matches!(colour, crate::cli::help::ColourChoice::Auto));
            }
            _ => panic!("expected Help command"),
        }
    }

    #[test]
    fn test_cli_parse_help_with_all_flags() {
        let cli = Cli::try_parse_from(&[
            "ssh-guard",
            "help",
            "--config",
            "/tmp/test.toml",
            "--profile",
            "admin",
            "--tree",
            "--verbose",
            "--colour",
            "always",
        ])
        .unwrap();
        match &cli.command {
            Command::Help {
                config,
                profile,
                tree,
                verbose,
                colour,
            } => {
                assert_eq!(config, "/tmp/test.toml");
                assert_eq!(profile.as_deref(), Some("admin"));
                assert!(*tree);
                assert!(*verbose);
                assert!(matches!(colour, crate::cli::help::ColourChoice::Always));
            }
            _ => panic!("expected Help command"),
        }
    }

    #[test]
    fn test_resolve_config_path_cli_arg_wins() {
        temp_env::with_var(CONFIG_ENV_VAR, Some("/env/path.toml"), || {
            let resolved = resolve_config_path(&Some("/cli/path.toml".to_string()));
            assert_eq!(resolved, "/cli/path.toml");
        });
    }

    #[test]
    fn test_resolve_config_path_env_var() {
        temp_env::with_var(CONFIG_ENV_VAR, Some("/env/path.toml"), || {
            let resolved = resolve_config_path(&None);
            assert_eq!(resolved, "/env/path.toml");
        });
    }

    #[test]
    fn test_resolve_config_path_default() {
        temp_env::with_var(CONFIG_ENV_VAR, None::<&str>, || {
            let resolved = resolve_config_path(&None);
            assert_eq!(resolved, DEFAULT_CONFIG_PATH);
        });
    }

    #[test]
    fn test_resolve_config_path_empty_env_falls_back() {
        temp_env::with_var(CONFIG_ENV_VAR, Some(""), || {
            let resolved = resolve_config_path(&None);
            assert_eq!(resolved, DEFAULT_CONFIG_PATH);
        });
    }

    #[test]
    fn test_cli_run_dispatch_errors_on_bad_config() {
        let cmd = Command::Run {
            config: Some("/tmp/nonexistent-ssh-guard-config.toml".to_string()),
        };
        let result = match &cmd {
            Command::Run { config } => run::run(config.as_deref().unwrap()),
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
            config: Some("/tmp/nonexistent-ssh-guard-config.toml".to_string()),
            cmd: "ls".to_string(),
            profile: None,
        };
        let result: Result<i32, Box<dyn std::error::Error>> = match &cmd {
            Command::AddRule {
                config,
                cmd,
                profile,
            } => merge::add_rule(config.as_deref().unwrap(), cmd, profile.as_deref())
                .map(|()| 0)
                .map_err(Into::into),
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
            config: Some("/tmp/nonexistent-ssh-guard-config.toml".to_string()),
        };
        let result: Result<i32, Box<dyn std::error::Error>> = match &cmd {
            Command::Validate { config } => {
                validate::validate(config.as_deref().unwrap()).map(|()| 0)
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
