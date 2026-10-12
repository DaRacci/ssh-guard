use super::types::TemplateType;
use crate::config::Config;
use crate::config::contract::Contract;
use crate::path_security::ensure_path_in_roots;

pub(crate) fn validate_template_value(
    value: &str,
    template: &TemplateType,
    config: &Config,
) -> Result<(), String> {
    match template {
        TemplateType::Named { inner, .. } => validate_template_value(value, inner, config),
        TemplateType::String => {
            if value.is_empty() {
                return Err("empty string not allowed".into());
            }
            Ok(())
        }
        TemplateType::Int => value
            .parse::<i64>()
            .map_err(|_| format!("'{value}' is not a valid integer"))
            .map(|_| ()),
        TemplateType::Any => Ok(()),
        TemplateType::ContractRef(name) => {
            let ct = config
                .contracts
                .get(name)
                .ok_or_else(|| format!("unknown contract '{name}'"))?;
            match ct {
                Contract::IntRange { min, max } => {
                    let n: i64 = value.parse().map_err(|_| {
                        format!("'{value}' is not a valid integer for contract '{name}'")
                    })?;
                    if n < *min || n > *max {
                        return Err(format!(
                            "'{value}' not in range [{min}, {max}] for contract '{name}'"
                        ));
                    }
                    Ok(())
                }
                Contract::StringLen { min, max } => {
                    let len = value.len();
                    if len < *min || len > *max {
                        return Err(format!(
                            "'{value}' length {len} not in range [{min}, {max}] for contract '{name}'"
                        ));
                    }
                    Ok(())
                }
                Contract::Enum { values } => {
                    if !values.contains(&value.to_string()) {
                        return Err(format!(
                            "'{value}' not in [{}] for contract '{name}'",
                            values.join(", ")
                        ));
                    }
                    Ok(())
                }
                Contract::Path {
                    root_set,
                    must_exist,
                } => {
                    let roots = config.root_set_paths(root_set).ok_or_else(|| {
                        format!("unknown root set '{root_set}' for contract '{name}'")
                    })?;
                    ensure_path_in_roots(std::path::Path::new(value), roots, *must_exist)
                        .map_err(|reason| format!("{reason} for contract '{name}'"))
                }
            }
        }
        TemplateType::Union(types) => {
            let mut errors = vec![];
            for t in types {
                match validate_template_value(value, t, config) {
                    Ok(()) => return Ok(()),
                    Err(e) => errors.push(e),
                }
            }
            Err(format!(
                "'{value}' matched none of the union: {}",
                errors.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::contract::Contract;
    use crate::config::{Config, Contracts};

    fn config_with_contracts(contracts: Contracts) -> Config {
        Config {
            contracts,
            ..Config::default()
        }
    }

    #[test]
    fn test_validate_int_ok() {
        let config = Config::default();
        assert!(validate_template_value("42", &TemplateType::Int, &config).is_ok());
    }

    #[test]
    fn test_validate_int_fail() {
        let config = Config::default();
        assert!(validate_template_value("abc", &TemplateType::Int, &config).is_err());
    }

    #[test]
    fn test_validate_union_ok() {
        let config = Config::default();
        let union = TemplateType::Union(vec![TemplateType::Int, TemplateType::String]);
        assert!(validate_template_value("42", &union, &config).is_ok());
        assert!(validate_template_value("hello", &union, &config).is_ok());
    }

    #[test]
    fn test_validate_union_fail() {
        let config = Config::default();
        let union = TemplateType::Union(vec![TemplateType::Int]);
        assert!(validate_template_value("hello", &union, &config).is_err());
    }

    #[test]
    fn test_validate_stringlen_contract_ok() {
        let mut contracts = Contracts::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        let config = config_with_contracts(contracts);
        assert!(
            validate_template_value("hello", &TemplateType::ContractRef("mystr".into()), &config)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_stringlen_contract_too_short() {
        let mut contracts = Contracts::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        let config = config_with_contracts(contracts);
        let result =
            validate_template_value("ab", &TemplateType::ContractRef("mystr".into()), &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("length"));
    }

    #[test]
    fn test_validate_stringlen_contract_too_long() {
        let mut contracts = Contracts::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        let config = config_with_contracts(contracts);
        let result = validate_template_value(
            "toolongvalue",
            &TemplateType::ContractRef("mystr".into()),
            &config,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("length"));
    }

    #[test]
    fn test_validate_contract_ref_unknown() {
        let config = Config::default();
        let result = validate_template_value(
            "anything",
            &TemplateType::ContractRef("nonexistent".into()),
            &config,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown contract"));
    }

    #[test]
    fn test_contract_int_range_boundary() {
        let mut contracts = Contracts::new();
        contracts.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        let config = config_with_contracts(contracts);
        assert!(
            validate_template_value("1024", &TemplateType::ContractRef("port".into()), &config)
                .is_ok()
        );
        assert!(
            validate_template_value("65535", &TemplateType::ContractRef("port".into()), &config)
                .is_ok()
        );
    }

    #[test]
    fn test_contract_int_range_just_outside() {
        let mut contracts = Contracts::new();
        contracts.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        let config = config_with_contracts(contracts);
        assert!(
            validate_template_value("1023", &TemplateType::ContractRef("port".into()), &config)
                .is_err()
        );
        assert!(
            validate_template_value("65536", &TemplateType::ContractRef("port".into()), &config)
                .is_err()
        );
    }

    #[test]
    fn test_validate_string_empty() {
        let config = Config::default();
        assert!(validate_template_value("", &TemplateType::String, &config).is_err());
        assert!(validate_template_value("a", &TemplateType::String, &config).is_ok());
    }

    #[test]
    fn test_contract_int_range_parse_error() {
        let mut contracts = Contracts::new();
        contracts.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        let config = config_with_contracts(contracts);
        let result =
            validate_template_value("abc", &TemplateType::ContractRef("port".into()), &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not a valid integer"));
    }
}
