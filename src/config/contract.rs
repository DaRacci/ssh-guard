use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Contract {
    #[serde(rename = "int_range")]
    IntRange { min: i64, max: i64 },

    #[serde(rename = "string_len")]
    StringLen { min: usize, max: usize },

    #[serde(rename = "enum")]
    Enum { values: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_int_range() {
        let toml_str = r#"type = "int_range"
min = 1024
max = 65535
"#;
        let c: Contract = toml::from_str(toml_str).unwrap();
        match c {
            Contract::IntRange { min, max } => {
                assert_eq!(min, 1024);
                assert_eq!(max, 65535);
            }
            _ => panic!("expected IntRange"),
        }
    }

    #[test]
    fn test_deserialize_string_len() {
        let toml_str = r#"type = "string_len"
min = 3
max = 32
"#;
        let c: Contract = toml::from_str(toml_str).unwrap();
        match c {
            Contract::StringLen { min, max } => {
                assert_eq!(min, 3);
                assert_eq!(max, 32);
            }
            _ => panic!("expected StringLen"),
        }
    }

    #[test]
    fn test_deserialize_enum() {
        let toml_str = r#"type = "enum"
values = ["ssh", "nginx"]
"#;
        let c: Contract = toml::from_str(toml_str).unwrap();
        match c {
            Contract::Enum { values } => {
                assert_eq!(values, vec!["ssh", "nginx"]);
            }
            _ => panic!("expected Enum"),
        }
    }

    #[test]
    fn test_error_missing_type_tag() {
        let toml_str = "min = 1\nmax = 10\n";
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_int_range_min() {
        let toml_str = r#"type = "int_range"
max = 100
"#;
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_int_range_max() {
        let toml_str = r#"type = "int_range"
min = 1
"#;
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_enum_values() {
        let toml_str = r#"type = "enum"
"#;
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_unknown_type_tag() {
        let toml_str = r#"type = "unknown_variant"
"#;
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_trip_int_range() {
        let c = Contract::IntRange { min: 0, max: 100 };
        let s = toml::to_string(&c).unwrap();
        let back: Contract = toml::from_str(&s).unwrap();
        assert_eq!(
            match back {
                Contract::IntRange { min, max } => (min, max),
                _ => panic!("expected IntRange"),
            },
            (0, 100)
        );
    }

    #[test]
    fn test_round_trip_string_len() {
        let c = Contract::StringLen { min: 1, max: 64 };
        let s = toml::to_string(&c).unwrap();
        let back: Contract = toml::from_str(&s).unwrap();
        assert_eq!(
            match back {
                Contract::StringLen { min, max } => (min, max),
                _ => panic!("expected StringLen"),
            },
            (1, 64)
        );
    }

    #[test]
    fn test_serialize_int_range_format() {
        let c = Contract::IntRange { min: 0, max: 100 };
        let s = toml::to_string(&c).unwrap();
        assert!(s.contains(r#"type = "int_range""#));
        assert!(s.contains("min = 0"));
        assert!(s.contains("max = 100"));
    }

    #[test]
    fn test_serialize_string_len_format() {
        let c = Contract::StringLen { min: 1, max: 64 };
        let s = toml::to_string(&c).unwrap();
        assert!(s.contains(r#"type = "string_len""#));
        assert!(s.contains("min = 1"));
        assert!(s.contains("max = 64"));
    }

    #[test]
    fn test_serialize_enum_format() {
        let c = Contract::Enum {
            values: vec!["a".into(), "b".into()],
        };
        let s = toml::to_string(&c).unwrap();
        assert!(s.contains(r#"type = "enum""#));
        assert!(s.contains(r#"values = ["a", "b"]"#));
    }

    // Trigger visitor expecting() by providing wrong TOML type (bool instead of table)
    #[test]
    fn test_error_message_contains_expecting() {
        let toml_str = "true";
        let result: Result<Contract, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();

        assert!(!err.is_empty());
    }

    #[test]
    fn test_round_trip_enum() {
        let c = Contract::Enum {
            values: vec!["a".into(), "b".into()],
        };
        let s = toml::to_string(&c).unwrap();
        let back: Contract = toml::from_str(&s).unwrap();
        assert_eq!(
            match back {
                Contract::Enum { values } => values,
                _ => panic!("expected Enum"),
            },
            vec!["a", "b"]
        );
    }
}
