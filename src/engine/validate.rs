use std::collections::HashMap;

use super::types::TemplateType;
use crate::config::contract::Contract;

pub(crate) fn validate_template_value(
    value: &str,
    template: &TemplateType,
    contracts: &HashMap<String, Contract>,
) -> Result<(), String> {
    match template {
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
            let ct = contracts
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
            }
        }
        TemplateType::Union(types) => {
            let mut errors = vec![];
            for t in types {
                match validate_template_value(value, t, contracts) {
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
    use std::collections::HashMap;

    #[test]
    fn test_validate_int_ok() {
        let contracts = HashMap::new();
        assert!(validate_template_value("42", &TemplateType::Int, &contracts).is_ok());
    }

    #[test]
    fn test_validate_int_fail() {
        let contracts = HashMap::new();
        assert!(validate_template_value("abc", &TemplateType::Int, &contracts).is_err());
    }

    #[test]
    fn test_validate_union_ok() {
        let contracts = HashMap::new();
        let union = TemplateType::Union(vec![TemplateType::Int, TemplateType::String]);
        assert!(validate_template_value("42", &union, &contracts).is_ok());
        assert!(validate_template_value("hello", &union, &contracts).is_ok());
    }

    #[test]
    fn test_validate_union_fail() {
        let contracts = HashMap::new();
        let union = TemplateType::Union(vec![TemplateType::Int]);
        assert!(validate_template_value("hello", &union, &contracts).is_err());
    }

    #[test]
    fn test_validate_stringlen_contract_ok() {
        let mut contracts = HashMap::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        assert!(
            validate_template_value(
                "hello",
                &TemplateType::ContractRef("mystr".into()),
                &contracts
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_stringlen_contract_too_short() {
        let mut contracts = HashMap::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        let result =
            validate_template_value("ab", &TemplateType::ContractRef("mystr".into()), &contracts);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("length"));
    }

    #[test]
    fn test_validate_stringlen_contract_too_long() {
        let mut contracts = HashMap::new();
        contracts.insert("mystr".into(), Contract::StringLen { min: 3, max: 10 });
        let result = validate_template_value(
            "toolongvalue",
            &TemplateType::ContractRef("mystr".into()),
            &contracts,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("length"));
    }

    #[test]
    fn test_validate_contract_ref_unknown() {
        let contracts = HashMap::new();
        let result = validate_template_value(
            "anything",
            &TemplateType::ContractRef("nonexistent".into()),
            &contracts,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown contract"));
    }

    #[test]
    fn test_contract_int_range_boundary() {
        let mut contracts = HashMap::new();
        contracts.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        assert!(
            validate_template_value(
                "1024",
                &TemplateType::ContractRef("port".into()),
                &contracts
            )
            .is_ok()
        );
        assert!(
            validate_template_value(
                "65535",
                &TemplateType::ContractRef("port".into()),
                &contracts
            )
            .is_ok()
        );
    }

    #[test]
    fn test_contract_int_range_just_outside() {
        let mut contracts = HashMap::new();
        contracts.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        assert!(
            validate_template_value(
                "1023",
                &TemplateType::ContractRef("port".into()),
                &contracts
            )
            .is_err()
        );
        assert!(
            validate_template_value(
                "65536",
                &TemplateType::ContractRef("port".into()),
                &contracts
            )
            .is_err()
        );
    }
}
