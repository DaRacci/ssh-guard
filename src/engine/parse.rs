use super::types::{ArgPattern, TemplateType};

pub(crate) fn parse_arg_pattern(raw: &str) -> ArgPattern {
    if let Some(eq_pos) = raw.find("={")
        && eq_pos > 0
        && raw.ends_with('}')
    {
        let flag = &raw[..eq_pos];
        let inner = &raw[eq_pos + 2..raw.len() - 1];
        let tmpl = parse_template_type(inner);
        return ArgPattern::InlineFlag {
            flag: flag.to_string(),
            template: tmpl,
        };
    }

    if raw.starts_with('{') && raw.ends_with('}') && raw.len() > 2 {
        let inner = &raw[1..raw.len() - 1];
        return ArgPattern::Template(parse_template_type(inner));
    }

    if let Some(open) = raw.find('{')
        && let Some(close) = raw[open..].find('}')
    {
        let abs_close = open + close;
        let template_inner = &raw[open + 1..abs_close];

        let prefix = if open > 0 {
            Some(raw[..open].to_string())
        } else {
            None
        };
        let suffix = if abs_close + 1 < raw.len() {
            Some(raw[abs_close + 1..].to_string())
        } else {
            None
        };

        if prefix.is_some() || suffix.is_some() {
            return ArgPattern::TemplateContext {
                prefix,
                template: parse_template_type(template_inner),
                suffix,
            };
        }
    }

    ArgPattern::Literal(raw.to_string())
}

pub(crate) fn parse_template_type(inner: &str) -> TemplateType {
    if inner.contains('|') {
        let parts: Vec<TemplateType> = inner
            .split('|')
            .map(|p| parse_single_template(p.trim()))
            .collect();
        return TemplateType::Union(parts);
    }
    parse_single_template(inner)
}

pub(crate) fn parse_single_template(s: &str) -> TemplateType {
    match s {
        "string" => TemplateType::String,
        "int" => TemplateType::Int,
        "any" => TemplateType::Any,
        other => TemplateType::ContractRef(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template_types(pattern: ArgPattern) -> Option<Vec<TemplateType>> {
        if let ArgPattern::Template(TemplateType::Union(types)) = pattern {
            Some(types)
        } else {
            None
        }
    }

    fn contract_ref_name(pattern: ArgPattern) -> Option<String> {
        if let ArgPattern::Template(TemplateType::ContractRef(name)) = pattern {
            Some(name)
        } else {
            None
        }
    }

    fn inline_flag(pattern: ArgPattern) -> Option<(String, TemplateType)> {
        if let ArgPattern::InlineFlag { flag, template } = pattern {
            Some((flag, template))
        } else {
            None
        }
    }

    fn template_context(
        pattern: ArgPattern,
    ) -> Option<(Option<String>, TemplateType, Option<String>)> {
        if let ArgPattern::TemplateContext {
            prefix,
            template,
            suffix,
        } = pattern
        {
            Some((prefix, template, suffix))
        } else {
            None
        }
    }

    #[test]
    fn test_parse_template_builtins() {
        let pattern_str = parse_arg_pattern("{string}");
        let pattern_int = parse_arg_pattern("{int}");
        let pattern_any = parse_arg_pattern("{any}");

        assert!(matches!(
            pattern_str,
            ArgPattern::Template(TemplateType::String)
        ));
        assert!(matches!(
            pattern_int,
            ArgPattern::Template(TemplateType::Int)
        ));
        assert!(matches!(
            pattern_any,
            ArgPattern::Template(TemplateType::Any)
        ));
    }

    #[test]
    fn test_parse_template_union() {
        let p = parse_arg_pattern("{int|string}");
        assert_eq!(
            template_types(p),
            Some(vec![TemplateType::Int, TemplateType::String])
        );
    }

    #[test]
    fn test_parse_template_contract() {
        let p = parse_arg_pattern("{port}");
        assert_eq!(contract_ref_name(p), Some("port".into()));
    }

    #[test]
    fn test_parse_inline_flag() {
        let p = parse_arg_pattern("--depth={int}");
        assert_eq!(inline_flag(p), Some(("--depth".into(), TemplateType::Int)));
    }

    #[test]
    fn test_parse_literal() {
        let p = parse_arg_pattern("--porcelain");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }

    #[test]
    fn test_parse_template_suffix() {
        let p = parse_arg_pattern("{unit}.service");
        assert_eq!(
            template_context(p),
            Some((
                None,
                TemplateType::ContractRef("unit".into()),
                Some(".service".into()),
            ))
        );
    }

    #[test]
    fn test_parse_template_suffix_numeric() {
        let p = parse_arg_pattern("{int}ms");
        assert_eq!(
            template_context(p),
            Some((None, TemplateType::Int, Some("ms".into())))
        );
    }

    #[test]
    fn test_parse_template_no_suffix_brace_only() {
        let p = parse_arg_pattern("{unit}");
        assert!(matches!(p, ArgPattern::Template(_)));
    }

    #[test]
    fn test_parse_template_context_prefix_only() {
        let p = parse_arg_pattern("--{unit}");
        assert_eq!(
            template_context(p),
            Some((
                Some("--".into()),
                TemplateType::ContractRef("unit".into()),
                None
            ))
        );
    }

    #[test]
    fn test_parse_template_context_both_sides() {
        let p = parse_arg_pattern("--{unit}.service");
        assert_eq!(
            template_context(p),
            Some((
                Some("--".into()),
                TemplateType::ContractRef("unit".into()),
                Some(".service".into()),
            ))
        );
    }

    #[test]
    fn test_parse_template_context_no_brace_no_context() {
        let p = parse_arg_pattern("--porcelain");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }

    #[test]
    fn test_parse_template_empty_brace() {
        let p = parse_arg_pattern("{}");
        assert!(!matches!(p, ArgPattern::Template(_)));
    }

    #[test]
    fn test_parse_template_nested_brace() {
        let p = parse_arg_pattern("{a{b}}");
        assert_eq!(contract_ref_name(p), Some("a{b}".into()));
    }

    #[test]
    fn test_parse_template_contract_not_defined() {
        let p = parse_arg_pattern("{mycontract}");
        assert_eq!(contract_ref_name(p), Some("mycontract".into()));
    }

    #[test]
    fn test_parse_inline_flag_dos() {
        let p = parse_arg_pattern("/flag:{int}");
        assert_eq!(
            template_context(p),
            Some((Some("/flag:".into()), TemplateType::Int, None))
        );
    }

    #[test]
    fn test_parse_union_three_types() {
        let p = parse_arg_pattern("{int|string|any}");
        assert_eq!(
            template_types(p),
            Some(vec![
                TemplateType::Int,
                TemplateType::String,
                TemplateType::Any
            ])
        );
    }

    #[test]
    fn test_parse_template_context_prefix_with_special_chars() {
        let p = parse_arg_pattern("--flag={int}");
        assert_eq!(inline_flag(p), Some(("--flag".into(), TemplateType::Int)));
    }

    #[test]
    fn test_parse_template_context_empty_prefix() {
        let p = parse_arg_pattern("{int}extra");
        assert_eq!(
            template_context(p),
            Some((None, TemplateType::Int, Some("extra".into())))
        );
    }

    #[test]
    fn test_parse_inline_flag_no_closing_brace() {
        let p = parse_arg_pattern("--flag={value");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }

    #[test]
    fn test_parse_eq_no_brace() {
        let p = parse_arg_pattern("--key=value");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }
}
