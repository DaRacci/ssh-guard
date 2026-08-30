use std::io::IsTerminal;

use crate::config::Config;
use crate::help::{HelpOptions, render_help};

#[derive(clap::ValueEnum, Clone, Copy, PartialEq)]
pub enum ColourChoice {
    Auto,
    Always,
    Never,
}

fn resolve_colour(choice: ColourChoice) -> bool {
    match choice {
        ColourChoice::Always => true,
        ColourChoice::Never => false,
        ColourChoice::Auto => {
            if std::env::var_os("NO_COLOR").is_some() {
                false
            } else {
                std::io::stdout().is_terminal()
            }
        }
    }
}

/// Render generated help from config.
///
/// # Errors
///
/// Returns error when config cannot be read or requested profile does not exist.
pub fn help(
    config_path: &str,
    profile: Option<&str>,
    tree: bool,
    verbose: bool,
    colour: ColourChoice,
) -> Result<i32, Box<dyn std::error::Error>> {
    let config = Config::from_file(config_path)?;

    let effective = match profile {
        Some(name) => {
            let profile = config.profiles.get(name).ok_or_else(|| {
                crate::errors::GuardError::Config(format!("profile '{name}' does not exist"))
            })?;
            config.merge_profile(profile)
        }
        None => config,
    };

    let opts = HelpOptions {
        tree,
        verbose,
        colour: resolve_colour(colour),
    };

    print!("{}", render_help(&effective, &opts));
    Ok(0)
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_colour_always() {
        assert!(resolve_colour(ColourChoice::Always));
    }

    #[test]
    fn test_resolve_colour_never() {
        assert!(!resolve_colour(ColourChoice::Never));
    }

    #[test]
    fn test_resolve_colour_auto_no_color_env() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            assert!(!resolve_colour(ColourChoice::Auto));
        });
    }
}
