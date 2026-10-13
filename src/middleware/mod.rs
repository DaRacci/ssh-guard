use crate::config::global::Global;

pub(crate) mod audit;

/// Build the default middleware chain for the `run` path.
pub(crate) fn default_chain(global: &Global) -> Chain {
    Chain::new(vec![Box::new(audit::Audit {
        log: global.audit_log.clone(),
        format: global.audit_format.clone(),
    })])
}

pub(crate) enum Decision {
    Continue,
    Deny(String),
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
            if let Decision::Deny(r) = m.on_request(s) {
                return Decision::Deny(r);
            }
        }

        Decision::Continue
    }

    pub(crate) fn on_match(&self, s: &Session<'_>, info: &MatchInfo<'_>) -> Decision {
        for m in &self.middleware {
            if let Decision::Deny(r) = m.on_match(s, info) {
                return Decision::Deny(r);
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
