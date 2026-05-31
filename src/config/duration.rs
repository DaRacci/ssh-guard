use serde::{Deserialize, Serialize};

const DEFAULT_DURATION_MS: u64 = 5000;

#[derive(Debug, Clone)]
pub struct Duration {
    pub millis: u64,
}

impl Default for Duration {
    fn default() -> Self {
        Self {
            millis: DEFAULT_DURATION_MS,
        }
    }
}

impl Serialize for Duration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}ms", self.millis))
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Duration;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a duration like \"5s\", \"5000ms\", or integer (ms)")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Duration, E> {
                Ok(Duration { millis: v as u64 })
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Duration, E> {
                Ok(Duration { millis: v })
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Duration, E> {
                parse_duration(s).map_err(E::custom)
            }
        }
        d.deserialize_any(Visitor)
    }
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.ends_with("ms") {
        let n: u64 = s[..s.len() - 2]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        return Ok(Duration { millis: n });
    }
    if s.ends_with('s') && !s.ends_with("ms") {
        let n: f64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        return Ok(Duration {
            millis: (n * 1000.0) as u64,
        });
    }
    if s.ends_with('m') && !s.ends_with("ms") {
        let n: f64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        return Ok(Duration {
            millis: (n * 60_000.0) as u64,
        });
    }
    if s.ends_with('h') {
        let n: f64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        return Ok(Duration {
            millis: (n * 3_600_000.0) as u64,
        });
    }

    // Bare integer = ms
    let n: u64 = s.parse().map_err(|_| format!("invalid duration: {s}"))?;
    Ok(Duration { millis: n })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zero_ms() {
        assert_eq!(parse_duration("0ms").unwrap().millis, 0);
    }

    #[test]
    fn test_parse_zero_bare() {
        assert_eq!(parse_duration("0").unwrap().millis, 0);
    }

    #[test]
    fn test_parse_zero_seconds() {
        assert_eq!(parse_duration("0s").unwrap().millis, 0);
    }

    #[test]
    fn test_parse_float_hours() {
        assert_eq!(parse_duration("1.5h").unwrap().millis, 5_400_000);
    }

    #[test]
    fn test_parse_float_minutes() {
        assert_eq!(parse_duration("2.5m").unwrap().millis, 150_000);
    }

    #[test]
    fn test_parse_float_seconds() {
        assert_eq!(parse_duration("0.5s").unwrap().millis, 500);
    }

    #[test]
    fn test_parse_whitespace() {
        assert_eq!(parse_duration(" 5s ").unwrap().millis, 5000);
    }

    #[test]
    fn test_parse_large_value() {
        assert_eq!(parse_duration("100h").unwrap().millis, 360_000_000);
    }

    #[test]
    fn test_parse_error_empty() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_error_abc() {
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn test_parse_negative_saturates_to_zero() {
        // Negative float cast to u64 saturates to 0
        assert_eq!(parse_duration("-5s").unwrap().millis, 0);
    }

    #[test]
    fn test_parse_error_unknown_suffix() {
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn test_parse_error_no_number() {
        assert!(parse_duration("ms").is_err());
    }

    // --- Default ---

    #[test]
    fn test_default_duration() {
        let d = Duration::default();
        assert_eq!(d.millis, 5000);
    }

    // --- Deserialize ---

    #[test]
    fn test_deserialize_integer() {
        let d: Duration = serde_json::from_str("10000").unwrap();
        assert_eq!(d.millis, 10000);
    }

    #[test]
    fn test_deserialize_string_seconds() {
        let d: Duration = serde_json::from_str(r#""30s""#).unwrap();
        assert_eq!(d.millis, 30000);
    }

    #[test]
    fn test_deserialize_string_ms() {
        let d: Duration = serde_json::from_str(r#""5000ms""#).unwrap();
        assert_eq!(d.millis, 5000);
    }

    // --- Serialize ---

    #[test]
    fn test_serialize_ms_format() {
        let d = Duration { millis: 5000 };
        assert_eq!(serde_json::to_string(&d).unwrap().trim(), r#""5000ms""#);
    }

    // --- Round-trip ---

    #[test]
    fn test_round_trip_integer() {
        let d = Duration { millis: 30000 };
        let s = serde_json::to_string(&d).unwrap();
        let back: Duration = serde_json::from_str(&s).unwrap();
        assert_eq!(back.millis, 30000);
    }

    #[test]
    fn test_round_trip_string() {
        let d: Duration = serde_json::from_str(r#""2m""#).unwrap();
        let s = serde_json::to_string(&d).unwrap();
        let back: Duration = serde_json::from_str(&s).unwrap();
        assert_eq!(back.millis, 120_000);
    }
}
