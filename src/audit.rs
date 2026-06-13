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

/// Get current time as ISO 8601 string without relying on an external crate.
pub(crate) fn chrono_now() -> String {
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

pub(crate) fn format_unix_time(secs: u64) -> String {
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

pub(crate) fn is_leap(y: i64) -> bool {
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
        let failures = vec!["rule[0]: token 2 '--bad' | unknown flag".into()];
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

    // ── format_unix_time ────────────────────────────────────────────

    #[test]
    fn test_format_unix_time_epoch() {
        assert_eq!(format_unix_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_one_day() {
        assert_eq!(format_unix_time(86400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_one_hour() {
        assert_eq!(format_unix_time(3600), "1970-01-01T01:00:00Z");
    }

    #[test]
    fn test_format_unix_time_leap_year_2000() {
        // 951782400 = 2000-02-29T00:00:00Z (leap year, Feb has 29 days)
        assert_eq!(format_unix_time(951782400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_non_leap_feb() {
        // 2001-03-01T00:00:00Z = 983404800 (non-leap, Feb has 28 days)
        assert_eq!(format_unix_time(983404800), "2001-03-01T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_midnight_boundary() {
        // Exactly one year after epoch: 1971-01-01T00:00:00Z
        let secs = 365 * 86400; // 1970 is not a leap year
        assert_eq!(format_unix_time(secs), "1971-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_leap_march_1() {
        // Day after Feb 29 in leap year 2000: 2000-03-01T00:00:00Z
        assert_eq!(format_unix_time(951868800), "2000-03-01T00:00:00Z");
    }

    #[test]
    fn test_format_unix_time_one_day_before_leap_feb_29() {
        // 951696000 = 2000-02-28T00:00:00Z (day before Feb 29 in leap year)
        assert_eq!(format_unix_time(951696000), "2000-02-28T00:00:00Z");
    }

    // ── is_leap ─────────────────────────────────────────────────────

    #[test]
    fn test_is_leap_2000() {
        assert!(is_leap(2000));
    }

    #[test]
    fn test_is_leap_2004() {
        assert!(is_leap(2004));
    }

    #[test]
    fn test_is_leap_1900() {
        assert!(!is_leap(1900));
    }

    #[test]
    fn test_is_leap_2001() {
        assert!(!is_leap(2001));
    }

    #[test]
    fn test_is_leap_2020() {
        assert!(is_leap(2020));
    }

    #[test]
    fn test_is_leap_2023() {
        assert!(!is_leap(2023));
    }

    #[test]
    fn test_is_leap_2400() {
        // Divisible by 400 → leap
        assert!(is_leap(2400));
    }

    #[test]
    fn test_is_leap_2100() {
        // Divisible by 100 but not 400 → not leap
        assert!(!is_leap(2100));
    }

    // ── denied with empty failures ──────────────────────────────────

    #[test]
    fn test_denied_empty_failures_no_failures_field() {
        let event = AuditEvent::denied("user", "cmd", "reason", &[]);
        let json = serde_json::to_string(&event).unwrap();
        // failures should be absent from JSON
        assert!(
            !json.contains("failures"),
            "empty failures vec should produce no 'failures' field, got: {json}"
        );
    }

    #[test]
    fn test_denied_with_failures_has_failures_field() {
        let failures = vec!["x".into(), "y".into()];
        let event = AuditEvent::denied("user", "cmd", "reason", &failures);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("failures"));
    }

    #[test]
    fn test_denied_empty_failures_logfmt_no_failures() {
        let event = AuditEvent::denied("user", "cmd", "reason", &[]);
        let line = event.to_logfmt();
        assert!(!line.contains("failures"));
    }

    // ── write_to (actual file I/O) ──────────────────────────────────

    #[test]
    fn test_write_to_json() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let event = AuditEvent::allowed("bob", "ls -la", "rule[0] ls");
        let fmt = AuditFormat::Json;
        event.write_to(&path, &fmt).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let trimmed = contents.trim();
        assert!(trimmed.starts_with("{"));
        assert!(trimmed.ends_with("}"));
        assert!(trimmed.contains("\"bob\""));
        assert!(trimmed.contains("\"allowed\""));

        // Append a second event
        let event2 = AuditEvent::allowed("alice", "pwd", "rule[0] pwd");
        event2.write_to(&path, &fmt).unwrap();

        let contents2 = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents2.trim().lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_write_to_logfmt() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let event = AuditEvent::denied(
            "mallory",
            "rm -rf /",
            "dangerous command",
            &["rule[0]: token 0 'rm' - blocked".into()],
        );
        let fmt = AuditFormat::Logfmt;
        event.write_to(&path, &fmt).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let trimmed = contents.trim();
        assert!(trimmed.starts_with("ts="));
        assert!(trimmed.contains("user=mallory"));
        assert!(trimmed.contains("result=denied"));
        assert!(trimmed.contains("failures="));
    }

    #[test]
    fn test_write_to_creates_file_if_not_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_audit.log");
        let path_str = path.to_str().unwrap().to_string();

        let event = AuditEvent::allowed("x", "y", "z");
        event.write_to(&path_str, &AuditFormat::Json).unwrap();

        assert!(path.exists());
        let contents = std::fs::read_to_string(&path_str).unwrap();
        assert!(!contents.is_empty());
    }
}
