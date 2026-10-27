use super::{Decision, MatchInfo, Middleware, Outcome, Session};

/// Reports a matched command without executing it when enabled.
pub(crate) struct DryRun {
    pub(crate) enabled: bool,
}

impl Middleware for DryRun {
    fn name(&self) -> &'static str {
        "dry_run"
    }

    fn on_match(&self, s: &Session<'_>, m: &MatchInfo<'_>) -> Decision {
        if !self.enabled {
            return Decision::Continue;
        }
        println!(
            "dry-run: command '{}' matched {}; not executed",
            s.command, m.detail
        );
        Decision::Handled {
            exit_code: 0,
            detail: "dry_run",
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

    fn info() -> MatchInfo<'static> {
        MatchInfo {
            rule_index: 0,
            subcommand_path: &[],
            detail: "rule[0] via ",
        }
    }

    #[test]
    fn test_dry_run_handles_when_enabled() {
        let mw = DryRun { enabled: true };
        assert!(matches!(
            mw.on_match(&session("ls"), &info()),
            Decision::Handled {
                exit_code: 0,
                detail: "dry_run"
            }
        ));
    }

    #[test]
    fn test_dry_run_continues_when_disabled() {
        let mw = DryRun { enabled: false };
        assert!(matches!(
            mw.on_match(&session("ls"), &info()),
            Decision::Continue
        ));
    }
}
