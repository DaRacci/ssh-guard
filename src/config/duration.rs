use crate::errors::{GuardError, Result};
use serde::{Deserialize, Serialize};
use std::{fmt::Result as FmtResult, result::Result as StdResult};

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
    fn serialize<S: serde::Serializer>(&self, s: S) -> StdResult<S::Ok, S::Error> {
        s.serialize_str(&format!("{}ms", self.millis))
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> StdResult<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Duration;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> FmtResult {
                f.write_str("a duration like \"5s\", \"5000ms\", or integer (ms)")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> StdResult<Duration, E> {
                Ok(Duration { millis: v as u64 })
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> StdResult<Duration, E> {
                Ok(Duration { millis: v })
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> StdResult<Duration, E> {
                parse_duration(s).map_err(E::custom)
            }
        }
        d.deserialize_any(Visitor)
    }
}

pub fn parse_duration(s: &str) -> Result<Duration> {
    const IDENTIFIER_MULTIPLIERS: [(&str, f64); 4] = [
        ("ms", 1.0),
        ("s", 1000.0),
        ("m", 60_000.0),
        ("h", 3_600_000.0),
    ];

    let s = s.trim().to_ascii_lowercase();
    let mut identifier = s
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();

    let raw_number = s[..s.len() - identifier.len()].trim();

    if identifier.is_empty() {
        identifier = "ms".to_string();
    }

    if IDENTIFIER_MULTIPLIERS
        .iter()
        .all(|(id, _)| id != &identifier)
    {
        return Err(GuardError::Config(format!(
            "invalid duration suffix: {identifier}"
        )));
    }

    let multiplier = IDENTIFIER_MULTIPLIERS
        .iter()
        .find(|(id, _)| *id == identifier)
        .map(|(_, mult)| *mult)
        .ok_or_else(|| GuardError::Config(format!("invalid duration suffix: {identifier}")))?; // This should never fail since we already found the identifier above

    let number = raw_number
        .parse::<f64>()
        .map_err(|_| GuardError::Config(format!("invalid duration number: {s}")))?;

    if number < 0.0 {
        return Err(GuardError::Config(format!(
            "duration cannot be negative: {s}"
        )));
    }

    let millis = (number * multiplier) as u64;
    return Ok(Duration { millis });
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

    // --- visit_i64 ---

    #[test]
    fn test_deserialize_negative_i64() {
        // visit_i64 with negative value should truncate to u64 (wrapping)
        let d: Duration = serde_json::from_str("-5000").unwrap();
        assert_eq!(d.millis, 18446744073709546616);
    }

    #[test]
    fn test_deserialize_positive_i64() {
        // visit_i64 with positive value
        let d: Duration = serde_json::from_str("10000").unwrap();
        assert_eq!(d.millis, 10000);
    }

    // --- expecting() via invalid deserialize type ---

    #[test]
    fn test_deserialize_bool_triggers_expecting() {
        // Deserializing a bool should trigger the visitor's expecting() message
        let result: StdResult<Duration, _> = serde_json::from_str("true");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duration"),
            "error should mention expected duration type: {err}"
        );
    }

    // --- visit_str with invalid string ---

    #[test]
    fn test_deserialize_invalid_string() {
        let result: StdResult<Duration, _> = serde_json::from_str(r#""not-a-duration""#);
        assert!(result.is_err());
    }

    // --- parse_duration additional cases ---

    #[test]
    fn test_parse_integer_hours() {
        assert_eq!(parse_duration("1h").unwrap().millis, 3_600_000);
    }

    #[test]
    fn test_parse_integer_minutes() {
        assert_eq!(parse_duration("2m").unwrap().millis, 120_000);
    }
}
