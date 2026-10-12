use super::types::{ArgPattern, TemplateType};

pub(crate) fn parse_arg_pattern(raw: &str) -> ArgPattern {
    let open = find_unescaped(raw, '{', 0);
    let ends_with_unescaped_close =
        raw.as_bytes().last() == Some(&b'}') && !is_escaped(raw, raw.len().saturating_sub(1));

    // Inline flag: `flag={template}` where the template closes the token.
    if let Some(open) = open
        && open > 0
        && raw.as_bytes()[open - 1] == b'='
        && ends_with_unescaped_close
    {
        let flag = unescape_braces(&raw[..open - 1]);
        let inner = &raw[open + 1..raw.len() - 1];
        return ArgPattern::InlineFlag {
            flag,
            template: parse_template_type(inner),
        };
    }

    // Whole-token template: `{template}`.
    // The outer braces are stripped without matching, so nested braces stay part of the template body.
    if open == Some(0) && ends_with_unescaped_close && raw.len() > 2 {
        let inner = &raw[1..raw.len() - 1];
        return ArgPattern::Template(parse_template_type(inner));
    }

    if let Some(open) = open
        && let Some(close) = find_unescaped(raw, '}', open + 1)
    {
        let prefix = if open > 0 {
            Some(unescape_braces(&raw[..open]))
        } else {
            None
        };
        let suffix = if close + 1 < raw.len() {
            Some(unescape_braces(&raw[close + 1..]))
        } else {
            None
        };

        if prefix.is_some() || suffix.is_some() {
            return ArgPattern::TemplateContext {
                prefix,
                template: parse_template_type(&raw[open + 1..close]),
                suffix,
            };
        }
    }

    ArgPattern::Literal(unescape_braces(raw))
}

/// Index of the first `target` character at or after `from` that is not backslash-escaped.
/// A backslash escapes the following character, and `\\` is an escaped backslash.
pub(crate) fn find_unescaped(s: &str, target: char, from: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let target = target as u8;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == target => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Whether the byte at `idx` is escaped by an odd run of preceding backslashes.
pub(crate) fn is_escaped(s: &str, idx: usize) -> bool {
    let bytes = s.as_bytes();
    let mut backslashes = 0;
    let mut i = idx;
    while i > 0 && bytes[i - 1] == b'\\' {
        backslashes += 1;
        i -= 1;
    }
    backslashes % 2 == 1
}

/// Resolve brace escapes.
/// A backslash before any other character is kept verbatim.
pub(crate) fn unescape_braces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }

        match chars.peek() {
            Some(&e @ ('{' | '}' | '\\')) => {
                out.push(e);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
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
    if let Some((name, rest)) = s.split_once(':')
        && is_valid_capture_name(name)
    {
        return TemplateType::Named {
            name: name.to_string(),
            inner: Box::new(parse_single_template(rest)),
        };
    }
    match s {
        "string" => TemplateType::String,
        "int" => TemplateType::Int,
        "any" => TemplateType::Any,
        other => TemplateType::ContractRef(other.to_string()),
    }
}

/// A capture name must be a usable map key: starts with a letter or underscore,
/// then letters/digits/underscores/hyphens.
fn is_valid_capture_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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
    fn test_parse_named_capture() {
        let p = parse_arg_pattern("{path:string}");
        match p {
            ArgPattern::Template(TemplateType::Named { name, inner }) => {
                assert_eq!(name, "path");
                assert_eq!(*inner, TemplateType::String);
            }
            _ => panic!("expected Named, got {p:?}"),
        }
    }

    #[test]
    fn test_parse_named_capture_contract() {
        let p = parse_arg_pattern("{path:port}");
        match p {
            ArgPattern::Template(TemplateType::Named { name, inner }) => {
                assert_eq!(name, "path");
                assert_eq!(*inner, TemplateType::ContractRef("port".into()));
            }
            _ => panic!("expected Named, got {p:?}"),
        }
    }

    #[test]
    fn test_parse_invalid_capture_name_falls_back() {
        // A colon after an invalid name is not a named capture. The whole
        // inner string is treated as a contract ref, as before.
        let p = parse_arg_pattern("{1bad:string}");
        match p {
            ArgPattern::Template(TemplateType::ContractRef(name)) => {
                assert_eq!(name, "1bad:string");
            }
            _ => panic!("expected ContractRef, got {p:?}"),
        }
    }

    #[test]
    fn test_capture_key_named_and_union() {
        let named = parse_template_type("path:string");
        assert_eq!(named.capture_key(), Some("path"));

        let contract = parse_template_type("port");
        assert_eq!(contract.capture_key(), Some("port"));

        let builtin = parse_template_type("string");
        assert_eq!(builtin.capture_key(), None);

        let union_same = parse_template_type("path:string|path:any");
        assert_eq!(union_same.capture_key(), Some("path"));

        let union_mixed = parse_template_type("path:string|other:string");
        assert_eq!(union_mixed.capture_key(), None);
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

    #[test]
    fn test_parse_escaped_braces_are_literal() {
        let p = parse_arg_pattern(r"--path=\{literal\}");
        match p {
            ArgPattern::Literal(lit) => assert_eq!(lit, "--path={literal}"),
            other => panic!("expected Literal, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_escaped_whole_brace_is_literal() {
        let p = parse_arg_pattern(r"\{int}");
        match p {
            ArgPattern::Literal(lit) => assert_eq!(lit, "{int}"),
            other => panic!("expected Literal, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_escaped_backslash_before_template() {
        let p = parse_arg_pattern(r"\\{int}");
        assert_eq!(
            template_context(p),
            Some((Some("\\".into()), TemplateType::Int, None))
        );
    }

    #[test]
    fn test_parse_unescapes_literal_prefix() {
        let p = parse_arg_pattern(r"a\{b}");
        match p {
            ArgPattern::Literal(lit) => assert_eq!(lit, "a{b}"),
            other => panic!("expected Literal, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_escaped_flag_with_inline_template() {
        let p = parse_arg_pattern(r"--a\{b\}={int}");
        assert_eq!(inline_flag(p), Some(("--a{b}".into(), TemplateType::Int)));
    }
}
