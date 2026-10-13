use super::{Decision, MatchInfo, Middleware, Outcome, Session};
use crate::audit::AuditEvent;
use crate::config::audit::AuditFormat;

pub(crate) struct Audit {
    pub(crate) log: String,
    pub(crate) format: AuditFormat,
}

impl Middleware for Audit {
    fn name(&self) -> &'static str {
        "audit"
    }

    fn on_match(&self, s: &Session<'_>, m: &MatchInfo<'_>) -> Decision {
        let _ = AuditEvent::started(s.user, s.command, m.detail, s.config_hash, s.session_id)
            .write_to(&self.log, &self.format);
        Decision::Continue
    }

    fn on_outcome(&self, s: &Session<'_>, o: &Outcome<'_>) {
        let event = match o {
            Outcome::Allowed { exit_code, detail } => AuditEvent::allowed(
                s.user,
                s.command,
                detail,
                *exit_code,
                s.config_hash,
                s.session_id,
            ),
            Outcome::Denied { reason, failures } => AuditEvent::denied(
                s.user,
                s.command,
                reason,
                failures,
                1,
                s.config_hash,
                s.session_id,
            ),
        };
        let _ = event.write_to(&self.log, &self.format);
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::middleware::{MatchInfo, Outcome, Session};

    fn session(command: &str) -> Session<'_> {
        Session {
            user: "u",
            command,
            session_id: "s",
            config_hash: "h",
        }
    }

    #[test]
    fn test_audit_writes_started_then_allowed() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let audit = Audit {
            log: tmp.path().to_str().unwrap().into(),
            format: AuditFormat::Json,
        };
        let info = MatchInfo {
            rule_index: 0,
            subcommand_path: &[String::new()],
            detail: "rule[0] via ",
        };

        assert!(matches!(
            audit.on_match(&session("ls"), &info),
            Decision::Continue
        ));
        audit.on_outcome(
            &session("ls"),
            &Outcome::Allowed {
                exit_code: 0,
                detail: "rule[0] via ",
            },
        );

        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"started\""));
        assert!(contents.contains("\"allowed\""));
    }

    #[test]
    fn test_audit_writes_denied_with_failures() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let audit = Audit {
            log: tmp.path().to_str().unwrap().into(),
            format: AuditFormat::Json,
        };
        let failures = vec!["rule[0]: bad".to_string()];

        audit.on_outcome(
            &session("ls"),
            &Outcome::Denied {
                reason: "no matching rule",
                failures: &failures,
            },
        );

        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("\"denied\""));
        assert!(contents.contains("bad"));
    }

    #[test]
    fn test_audit_write_failure_is_non_fatal() {
        let audit = Audit {
            log: "/nonexistent-dir-xyz/audit.log".into(),
            format: AuditFormat::Json,
        };
        // must not panic
        audit.on_outcome(
            &session("ls"),
            &Outcome::Allowed {
                exit_code: 0,
                detail: "d",
            },
        );
    }
}
