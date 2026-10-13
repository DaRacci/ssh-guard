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
        Request,
        Match,
        Outcome(String),
    }

    struct Recorder {
        calls: Arc<Mutex<Vec<Call>>>,
        deny_match: bool,
    }

    impl Middleware for Recorder {
        fn name(&self) -> &'static str {
            "recorder"
        }
        fn on_request(&self, _s: &Session<'_>) -> Decision {
            self.calls.lock().unwrap().push(Call::Request);
            Decision::Continue
        }
        fn on_match(&self, _s: &Session<'_>, _m: &MatchInfo<'_>) -> Decision {
            self.calls.lock().unwrap().push(Call::Match);
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
            self.calls.lock().unwrap().push(Call::Outcome(tag));
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
        let denier = Recorder {
            calls: calls.clone(),
            deny_match: true,
        };
        let after = Recorder {
            calls: calls.clone(),
            deny_match: false,
        };
        let chain = Chain::new(vec![Box::new(denier), Box::new(after)]);

        let decision = chain.on_match(&session(), &info());
        assert!(matches!(decision, Decision::Deny(r) if r == "nope"));
        // second middleware's on_match must NOT run
        assert_eq!(*calls.lock().unwrap(), vec![Call::Match]);
    }

    #[test]
    fn test_chain_on_outcome_runs_all_in_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let a = Recorder {
            calls: calls.clone(),
            deny_match: false,
        };
        let b = Recorder {
            calls: calls.clone(),
            deny_match: false,
        };
        let chain = Chain::new(vec![Box::new(a), Box::new(b)]);

        chain.on_outcome(
            &session(),
            &Outcome::Allowed {
                exit_code: 0,
                detail: "d",
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                Call::Outcome("allowed".into()),
                Call::Outcome("allowed".into())
            ]
        );
    }

    #[test]
    fn test_chain_on_request_passes_when_all_continue() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let a = Recorder {
            calls: calls.clone(),
            deny_match: false,
        };
        let chain = Chain::new(vec![Box::new(a)]);

        assert!(matches!(chain.on_request(&session()), Decision::Continue));
        assert_eq!(*calls.lock().unwrap(), vec![Call::Request]);
    }
}
