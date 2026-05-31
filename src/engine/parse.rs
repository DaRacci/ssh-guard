use super::types::{ArgPattern, TemplateType};

pub(crate) fn parse_arg_pattern(raw: &str) -> ArgPattern {
    // Inline flag: "--flag={...}" — requires '=' before '{'
    if let Some(eq_pos) = raw.find("={") {
        if eq_pos > 0 && raw.ends_with('}') {
            let flag = &raw[..eq_pos];
            let inner = &raw[eq_pos + 2..raw.len() - 1];
            let tmpl = parse_template_type(inner);
            return ArgPattern::InlineFlag {
                flag: flag.to_string(),
                template: tmpl,
            };
        }
    }

    // Standalone template: "{...}" with nothing outside braces
    if raw.starts_with('{') && raw.ends_with('}') && raw.len() > 2 {
        let inner = &raw[1..raw.len() - 1];
        return ArgPattern::Template(parse_template_type(inner));
    }

    // Template with context: prefix{type} or {type}suffix or prefix{type}suffix
    if let Some(open) = raw.find('{') {
        if let Some(close) = raw[open..].find('}') {
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
    }

    // 4. Literal
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
        match p {
            ArgPattern::Template(TemplateType::Union(types)) => {
                assert_eq!(types.len(), 2);
                assert_eq!(types[0], TemplateType::Int);
                assert_eq!(types[1], TemplateType::String);
            }
            _ => panic!("expected Union"),
        }
    }

    #[test]
    fn test_parse_template_contract() {
        let p = parse_arg_pattern("{port}");
        match p {
            ArgPattern::Template(TemplateType::ContractRef(name)) => {
                assert_eq!(name, "port");
            }
            _ => panic!("expected ContractRef"),
        }
    }

    #[test]
    fn test_parse_inline_flag() {
        let p = parse_arg_pattern("--depth={int}");
        match p {
            ArgPattern::InlineFlag { flag, template } => {
                assert_eq!(flag, "--depth");
                assert_eq!(template, TemplateType::Int);
            }
            _ => panic!("expected InlineFlag"),
        }
    }

    #[test]
    fn test_parse_literal() {
        let p = parse_arg_pattern("--porcelain");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }

    #[test]
    fn test_parse_template_suffix() {
        let p = parse_arg_pattern("{unit}.service");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, None);
                assert_eq!(template, TemplateType::ContractRef("unit".into()));
                assert_eq!(suffix, Some(".service".into()));
            }
            _ => panic!("expected TemplateContext, got {:?}", p),
        }
    }

    #[test]
    fn test_parse_template_suffix_numeric() {
        let p = parse_arg_pattern("{int}ms");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, None);
                assert_eq!(template, TemplateType::Int);
                assert_eq!(suffix, Some("ms".into()));
            }
            _ => panic!("expected TemplateContext"),
        }
    }

    #[test]
    fn test_parse_template_no_suffix_brace_only() {
        let p = parse_arg_pattern("{unit}");
        assert!(matches!(p, ArgPattern::Template(_)));
    }

    #[test]
    fn test_parse_template_context_prefix_only() {
        let p = parse_arg_pattern("--{unit}");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, Some("--".into()));
                assert_eq!(template, TemplateType::ContractRef("unit".into()));
                assert_eq!(suffix, None);
            }
            _ => panic!("expected TemplateContext, got {:?}", p),
        }
    }

    #[test]
    fn test_parse_template_context_both_sides() {
        let p = parse_arg_pattern("--{unit}.service");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, Some("--".into()));
                assert_eq!(template, TemplateType::ContractRef("unit".into()));
                assert_eq!(suffix, Some(".service".into()));
            }
            _ => panic!("expected TemplateContext, got {:?}", p),
        }
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
        match p {
            ArgPattern::Template(TemplateType::ContractRef(name)) => {
                assert_eq!(name, "a{b}");
            }
            _ => panic!("expected Template(ContractRef), got {p:?}"),
        }
    }

    #[test]
    fn test_parse_template_contract_not_defined() {
        let p = parse_arg_pattern("{mycontract}");
        match p {
            ArgPattern::Template(TemplateType::ContractRef(name)) => {
                assert_eq!(name, "mycontract");
            }
            _ => panic!("expected ContractRef"),
        }
    }

    #[test]
    fn test_parse_inline_flag_dos() {
        let p = parse_arg_pattern("/flag:{int}");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, Some("/flag:".into()));
                assert_eq!(template, TemplateType::Int);
                assert_eq!(suffix, None);
            }
            _ => panic!("expected TemplateContext, got {p:?}"),
        }
    }

    #[test]
    fn test_parse_union_three_types() {
        let p = parse_arg_pattern("{int|string|any}");
        match p {
            ArgPattern::Template(TemplateType::Union(types)) => {
                assert_eq!(types.len(), 3);
                assert_eq!(types[0], TemplateType::Int);
                assert_eq!(types[1], TemplateType::String);
                assert_eq!(types[2], TemplateType::Any);
            }
            _ => panic!("expected Union of 3"),
        }
    }

    #[test]
    fn test_parse_template_context_prefix_with_special_chars() {
        let p = parse_arg_pattern("--flag={int}");
        match p {
            ArgPattern::InlineFlag { flag, template } => {
                assert_eq!(flag, "--flag");
                assert_eq!(template, TemplateType::Int);
            }
            _ => panic!("expected InlineFlag, got {p:?}"),
        }
    }

    #[test]
    fn test_parse_template_context_empty_prefix() {
        let p = parse_arg_pattern("{int}extra");
        match p {
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                assert_eq!(prefix, None);
                assert_eq!(template, TemplateType::Int);
                assert_eq!(suffix, Some("extra".into()));
            }
            _ => panic!("expected TemplateContext, got {p:?}"),
        }
    }

    #[test]
    fn test_parse_inline_flag_no_closing_brace() {
        // raw has "={" but no closing '}' → falls through to template/literal
        let p = parse_arg_pattern("--flag={value");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }

    #[test]
    fn test_parse_eq_no_brace() {
        // raw has "=" but not "={" — literal
        let p = parse_arg_pattern("--key=value");
        assert!(matches!(p, ArgPattern::Literal(_)));
    }
}
