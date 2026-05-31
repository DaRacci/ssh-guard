use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ArgStyle {
    #[default]
    GnuLong,
    PosixShort,
    Dos,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_gnu_long() {
        let style = ArgStyle::default();
        assert_eq!(style, ArgStyle::GnuLong);
    }

    #[test]
    fn test_deserialize_gnu_long() {
        let style: ArgStyle = serde_json::from_str(r#""gnu_long""#).unwrap();
        assert_eq!(style, ArgStyle::GnuLong);
    }

    #[test]
    fn test_deserialize_posix_short() {
        let style: ArgStyle = serde_json::from_str(r#""posix_short""#).unwrap();
        assert_eq!(style, ArgStyle::PosixShort);
    }

    #[test]
    fn test_deserialize_dos() {
        let style: ArgStyle = serde_json::from_str(r#""dos""#).unwrap();
        assert_eq!(style, ArgStyle::Dos);
    }

    #[test]
    fn test_deserialize_invalid_variant() {
        let result: Result<ArgStyle, _> = serde_json::from_str(r#""invalid_style""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&ArgStyle::GnuLong).unwrap().trim(),
            r#""gnu_long""#
        );
        assert_eq!(
            serde_json::to_string(&ArgStyle::PosixShort).unwrap().trim(),
            r#""posix_short""#
        );
        assert_eq!(
            serde_json::to_string(&ArgStyle::Dos).unwrap().trim(),
            r#""dos""#
        );
    }

    #[test]
    fn test_round_trip() {
        for v in [ArgStyle::GnuLong, ArgStyle::PosixShort, ArgStyle::Dos] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ArgStyle = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(ArgStyle::GnuLong, ArgStyle::GnuLong);
        assert_eq!(ArgStyle::PosixShort, ArgStyle::PosixShort);
        assert_eq!(ArgStyle::Dos, ArgStyle::Dos);
        assert_ne!(ArgStyle::GnuLong, ArgStyle::PosixShort);
        assert_ne!(ArgStyle::GnuLong, ArgStyle::Dos);
        assert_ne!(ArgStyle::PosixShort, ArgStyle::Dos);
    }
}
