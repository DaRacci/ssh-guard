use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditFormat {
    #[default]
    Json,
    Logfmt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_json() {
        let fmt = AuditFormat::default();
        assert_eq!(fmt, AuditFormat::Json);
    }

    #[test]
    fn test_deserialize_json() {
        let fmt: AuditFormat = serde_json::from_str(r#""json""#).unwrap();
        assert_eq!(fmt, AuditFormat::Json);
    }

    #[test]
    fn test_deserialize_logfmt() {
        let fmt: AuditFormat = serde_json::from_str(r#""logfmt""#).unwrap();
        assert_eq!(fmt, AuditFormat::Logfmt);
    }

    #[test]
    fn test_deserialize_invalid_variant() {
        let result: Result<AuditFormat, _> = serde_json::from_str(r#""xml""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuditFormat::Json).unwrap().trim(),
            r#""json""#
        );
        assert_eq!(
            serde_json::to_string(&AuditFormat::Logfmt).unwrap().trim(),
            r#""logfmt""#
        );
    }

    #[test]
    fn test_round_trip() {
        for v in [AuditFormat::Json, AuditFormat::Logfmt] {
            let s = serde_json::to_string(&v).unwrap();
            let back: AuditFormat = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(AuditFormat::Json, AuditFormat::Json);
        assert_eq!(AuditFormat::Logfmt, AuditFormat::Logfmt);
        assert_ne!(AuditFormat::Json, AuditFormat::Logfmt);
    }
}
