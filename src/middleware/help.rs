use super::{Decision, Middleware, Outcome, Session};

/// Handles an empty `SSH_ORIGINAL_COMMAND` by printing the configured help text
/// and short-circuiting the run with a successful exit.
pub(crate) struct Help {
    pub(crate) text: String,
}

impl Middleware for Help {
    fn name(&self) -> &'static str {
        "help"
    }

    fn on_request(&self, s: &Session<'_>) -> Decision {
        if s.command.trim().is_empty() {
            println!("{}", self.text);
            Decision::Handled {
                exit_code: 0,
                detail: "show_help",
            }
        } else {
            Decision::Continue
        }
    }

    fn on_outcome(&self, _s: &Session<'_>, _o: &Outcome<'_>) {}
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;

    fn session(command: &str) -> Session<'_> {
        Session {
            user: "u",
            command,
            session_id: "s",
            config_hash: "h",
        }
    }

    #[test]
    fn test_help_handles_empty_command() {
        let help = Help {
            text: "help".into(),
        };
        assert!(matches!(
            help.on_request(&session("")),
            Decision::Handled {
                exit_code: 0,
                detail: "show_help"
            }
        ));
    }

    #[test]
    fn test_help_handles_whitespace_only_command() {
        let help = Help {
            text: "help".into(),
        };
        assert!(matches!(
            help.on_request(&session("   ")),
            Decision::Handled { .. }
        ));
    }

    #[test]
    fn test_help_continues_for_non_empty_command() {
        let help = Help {
            text: "help".into(),
        };
        assert!(matches!(
            help.on_request(&session("ls")),
            Decision::Continue
        ));
    }
}
