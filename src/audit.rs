use crate::config::audit::AuditFormat;
use serde::Serialize;
use std::io::Write;

/// A single audit event written to the audit log.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,

    /// The Unix username that ran the command (from SSH).
    pub user: String,

    /// The full SSH_ORIGINAL_COMMAND string.
    pub command: String,

    /// "allowed" or "denied".
    pub result: String,

    /// For allowed: the rule + subcommand path.
    /// For denied: the rejection reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// For denied: list of attempted match failures (serialized as JSON array).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<String>>,
}

impl AuditEvent {
    pub fn allowed(user: &str, command: &str, detail: &str) -> Self {
        Self {
            timestamp: chrono_now(),
            user: user.into(),
            command: command.into(),
            result: "allowed".into(),
            detail: Some(detail.into()),
            failures: None,
        }
    }

    pub fn denied(user: &str, command: &str, reason: &str, failures: &[String]) -> Self {
        let f = if failures.is_empty() {
            None
        } else {
            Some(failures.to_vec())
        };
        Self {
            timestamp: chrono_now(),
            user: user.into(),
            command: command.into(),
            result: "denied".into(),
            detail: Some(reason.into()),
            failures: f,
        }
    }

    /// Append this event to the audit log file.
    pub fn write_to(
        &self,
        path: &str,
        format: &AuditFormat,
    ) -> Result<(), crate::errors::GuardError> {
        let line = match format {
            AuditFormat::Json => serde_json::to_string(self)
                .map_err(|e| crate::errors::GuardError::Action(format!("audit serialize: {e}")))?,
            AuditFormat::Logfmt => self.to_logfmt(),
        };

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        writeln!(file, "{line}")?;
        Ok(())
    }

    fn to_logfmt(&self) -> String {
        let mut parts = vec![
            format!("ts={}", self.timestamp),
            format!("user={}", self.user),
            format!("command=\"{}\"", self.command),
            format!("result={}", self.result),
        ];
        if let Some(ref d) = self.detail {
            parts.push(format!("detail=\"{}\"", d));
        }
        if let Some(ref f) = self.failures {
            parts.push(format!("failures=\"{}\"", f.join("; ")));
        }
        parts.join(" ")
    }
}

/// Get current time as ISO 8601 string (no external crate — manual formatting).
fn chrono_now() -> String {
    // Use UNIX epoch + format manually to avoid chrono dependency.
    // Format: "2025-01-15T10:30:00Z"
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple: just format seconds since epoch. A real impl would parse to date.
    // For dependency-free approach, use the built-in way.
    format_unix_time(secs)
}

fn format_unix_time(secs: u64) -> String {
    // Days since epoch
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days to year/month/day (approximate, no leap-second handling)
    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md as i64 {
            m = i + 1;
            break;
        }
        remaining_days -= md as i64;
    }

    let d = remaining_days as u64 + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_json() {
        let event = AuditEvent::allowed(
            "ai-agent",
            "systemctl status sshd",
            "rule[0] systemctl/status",
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"allowed\""));
        assert!(json.contains("ai-agent"));
        assert!(json.contains("systemctl status sshd"));
    }

    #[test]
    fn test_audit_event_denied() {
        let failures = vec!["rule[0]: token 2 '--bad' — unknown flag".into()];
        let event =
            AuditEvent::denied("ai-agent", "systemctl --bad", "no matching rule", &failures);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"denied\""));
        assert!(json.contains("--bad"));
    }

    #[test]
    fn test_audit_event_logfmt() {
        let event = AuditEvent::allowed("agent", "help", "show_help");
        let line = event.to_logfmt();
        assert!(line.starts_with("ts="));
        assert!(line.contains("user=agent"));
        assert!(line.contains("result=allowed"));
    }

    #[test]
    fn test_timestamp_format() {
        let ts = chrono_now();
        // Should look like ISO 8601
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
        assert_eq!(ts.len(), 20); // "YYYY-MM-DDTHH:MM:SSZ"
    }
}
