use crate::config::Config;

pub(crate) mod audit;
pub(crate) mod dry_run;
pub(crate) mod help;

/// Build the default middleware chain for the `run` path.
///
/// Order matters: `DryRun` runs before `Audit` so a dry-run match is audited as
/// allowed without a `started` record (nothing executes). `Audit` then records
/// outcomes, and `Help` handles the empty-command and raw `help` request before
/// matching.
pub(crate) fn default_chain(config: &Config) -> Chain {
    let global = &config.global;
    Chain::new(vec![
        Box::new(dry_run::DryRun {
            enabled: global.dry_run,
        }),
        Box::new(audit::Audit {
            log: global.audit_log.clone(),
            format: global.audit_format.clone(),
        }),
        Box::new(help::Help {
            text: crate::help::resolved_help(config),
        }),
    ])
}

pub(crate) enum Decision {
    /// Continue to the next middleware in the chain.
    Continue,

    /// Veto a request or match.
    ///
    /// The middleware may log the reason for the denial, but it is not surfaced to the user.
    #[allow(dead_code)]
    Deny(String),

    /// The middleware handled the request itself and short-circuited the run.
    Handled {
        exit_code: i32,
        detail: &'static str,
    },
}

pub(crate) struct Session<'a> {
    pub user: &'a str,
    pub command: &'a str,
    #[allow(clippy::struct_field_names)]
    pub session_id: &'a str,
    pub config_hash: &'a str,
}

pub(crate) struct MatchInfo<'a> {
    pub rule_index: usize,
    pub subcommand_path: &'a [String],
    pub detail: &'a str,
}

pub(crate) enum Outcome<'a> {
    Allowed {
        exit_code: i32,
        detail: &'a str,
    },
    Denied {
        reason: &'a str,
        failures: &'a [String],
    },
}

pub(crate) trait Middleware: Sync {
    fn name(&self) -> &'static str;

    fn on_request(&self, _s: &Session<'_>) -> Decision {
        Decision::Continue
    }

    fn on_match(&self, _s: &Session<'_>, _m: &MatchInfo<'_>) -> Decision {
        Decision::Continue
    }

    fn on_outcome(&self, _s: &Session<'_>, _o: &Outcome<'_>);
}

pub(crate) struct Chain {
    middleware: Vec<Box<dyn Middleware>>,
}

impl Chain {
    pub(crate) fn new(middleware: Vec<Box<dyn Middleware>>) -> Self {
        Self { middleware }
    }

    pub(crate) fn on_request(&self, s: &Session<'_>) -> Decision {
        for m in &self.middleware {
            match m.on_request(s) {
                Decision::Continue => {}
                Decision::Deny(r) => {
                    let name = m.name();
                    log::debug!("middleware '{name}' denied request");
                    return Decision::Deny(r);
                }
                handled @ Decision::Handled { .. } => {
                    let name = m.name();
                    log::debug!("middleware '{name}' handled request");
                    return handled;
                }
            }
        }

        Decision::Continue
    }

    pub(crate) fn on_match(&self, s: &Session<'_>, info: &MatchInfo<'_>) -> Decision {
        for m in &self.middleware {
            match m.on_match(s, info) {
                Decision::Continue => {}
                Decision::Deny(r) => {
                    let name = m.name();
                    let path = info.subcommand_path.join("/");
                    log::debug!(
                        "middleware '{name}' denied rule[{}] via {path}",
                        info.rule_index
                    );
                    return Decision::Deny(r);
                }
                handled @ Decision::Handled { .. } => {
                    let name = m.name();
                    log::debug!("middleware '{name}' handled rule[{}]", info.rule_index);
                    return handled;
                }
            }
        }
        Decision::Continue
    }

    pub(crate) fn on_outcome(&self, s: &Session<'_>, o: &Outcome<'_>) {
        for m in &self.middleware {
            m.on_outcome(s, o);
        }
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, PartialEq)]
    enum Call {
        Request(&'static str),
        Match(&'static str),
        Outcome(String),
    }

    struct Recorder {
        label: &'static str,
        calls: Arc<Mutex<Vec<Call>>>,
        deny_request: bool,
        deny_match: bool,
    }

    impl Recorder {
        fn new(label: &'static str, calls: &Arc<Mutex<Vec<Call>>>) -> Self {
            Self {
                label,
                calls: calls.clone(),
                deny_request: false,
                deny_match: false,
            }
        }

        fn denying_request(mut self) -> Self {
            self.deny_request = true;
            self
        }

        fn denying_match(mut self) -> Self {
            self.deny_match = true;
            self
        }
    }

    impl Middleware for Recorder {
        fn name(&self) -> &'static str {
            "recorder"
        }

        fn on_request(&self, _s: &Session<'_>) -> Decision {
            self.calls.lock().unwrap().push(Call::Request(self.label));
            if self.deny_request {
                Decision::Deny("nope".into())
            } else {
                Decision::Continue
            }
        }

        fn on_match(&self, _s: &Session<'_>, _m: &MatchInfo<'_>) -> Decision {
            self.calls.lock().unwrap().push(Call::Match(self.label));
            if self.deny_match {
                Decision::Deny("nope".into())
            } else {
                Decision::Continue
            }
        }

        fn on_outcome(&self, _s: &Session<'_>, o: &Outcome<'_>) {
            let tag = match o {
                Outcome::Allowed { .. } => "allowed".to_string(),
                Outcome::Denied { reason, .. } => format!("denied:{reason}"),
            };
            self.calls
                .lock()
                .unwrap()
                .push(Call::Outcome(format!("{}:{tag}", self.label)));
        }
    }

    fn session() -> Session<'static> {
        Session {
            user: "u",
            command: "cmd",
            session_id: "s",
            config_hash: "h",
        }
    }
    fn info() -> MatchInfo<'static> {
        MatchInfo {
            rule_index: 0,
            subcommand_path: &[],
            detail: "d",
        }
    }

    struct Handler(&'static str);

    impl Middleware for Handler {
        fn name(&self) -> &'static str {
            "handler"
        }

        fn on_request(&self, _s: &Session<'_>) -> Decision {
            Decision::Handled {
                exit_code: 0,
                detail: self.0,
            }
        }

        fn on_outcome(&self, _s: &Session<'_>, _o: &Outcome<'_>) {}
    }

    #[test]
    fn test_chain_on_request_short_circuits_on_handled() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![
            Box::new(Handler("show_help")),
            Box::new(Recorder::new("b", &calls)),
        ]);

        assert!(matches!(
            chain.on_request(&session()),
            Decision::Handled {
                exit_code: 0,
                detail: "show_help"
            }
        ));
        // the later middleware must not run
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn test_chain_on_match_short_circuits_on_deny() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![
            Box::new(Recorder::new("a", &calls).denying_match()),
            Box::new(Recorder::new("b", &calls)),
        ]);

        let decision = chain.on_match(&session(), &info());
        assert!(matches!(decision, Decision::Deny(r) if r == "nope"));
        // second middleware's on_match must NOT run
        assert_eq!(*calls.lock().unwrap(), vec![Call::Match("a")]);
    }

    #[test]
    fn test_chain_on_match_passes_when_all_continue() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![
            Box::new(Recorder::new("a", &calls)),
            Box::new(Recorder::new("b", &calls)),
        ]);

        assert!(matches!(
            chain.on_match(&session(), &info()),
            Decision::Continue
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            vec![Call::Match("a"), Call::Match("b")]
        );
    }

    #[test]
    fn test_chain_on_outcome_runs_all_in_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![
            Box::new(Recorder::new("a", &calls)),
            Box::new(Recorder::new("b", &calls)),
        ]);

        chain.on_outcome(
            &session(),
            &Outcome::Allowed {
                exit_code: 0,
                detail: "d",
            },
        );
        // Distinct labels prove execution order, not merely the call count.
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                Call::Outcome("a:allowed".into()),
                Call::Outcome("b:allowed".into())
            ]
        );
    }

    #[test]
    fn test_chain_on_request_short_circuits_on_deny() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![
            Box::new(Recorder::new("a", &calls).denying_request()),
            Box::new(Recorder::new("b", &calls)),
        ]);

        let decision = chain.on_request(&session());
        assert!(matches!(decision, Decision::Deny(r) if r == "nope"));
        // second middleware's on_request must NOT run
        assert_eq!(*calls.lock().unwrap(), vec![Call::Request("a")]);
    }

    #[test]
    fn test_chain_on_request_passes_when_all_continue() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = Chain::new(vec![Box::new(Recorder::new("a", &calls))]);

        assert!(matches!(chain.on_request(&session()), Decision::Continue));
        assert_eq!(*calls.lock().unwrap(), vec![Call::Request("a")]);
    }
}
