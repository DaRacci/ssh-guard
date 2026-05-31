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
        Command::AddRule { config, cmd } => merge::add_rule(config, cmd)
            .map(|_| 0)
            .map_err(|e| e.into()),
        Command::Validate { config } => validate::validate(config).map(|_| 0).map_err(|e| e.into()),
    }
}
