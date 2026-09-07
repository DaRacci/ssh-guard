use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TemplateType {
    String,
    Int,
    Any,
    /// Explicitly named capture (`{name:template}`): the matched value is
    /// stored under `name` and validated against the inner template.
    Named {
        name: String,
        inner: Box<TemplateType>,
    },
    ContractRef(String),
    Union(Vec<TemplateType>),
}

impl TemplateType {
    /// The explicit capture key this template stores its matched value under,
    /// if it always captures under one name. `None` means the capture is
    /// stored positionally (`arg_0`, `arg_1`, ...).
    ///
    /// - `{name:template}` -> `Some(name)`
    /// - `{contract}` -> `Some(contract)`
    /// - `{string}`, `{int}`, `{any}` -> `None`
    /// - unions -> `Some(name)` only when every member shares one name
    pub(crate) fn capture_key(&self) -> Option<&str> {
        match self {
            TemplateType::Named { name, .. } | TemplateType::ContractRef(name) => Some(name),
            TemplateType::Union(parts) => {
                let name = parts.first()?.capture_key()?;
                if parts.iter().all(|p| p.capture_key() == Some(name)) {
                    Some(name)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ArgPattern {
    Literal(String),
    Template(TemplateType),
    /// Template with literal prefix and/or suffix
    TemplateContext {
        prefix: Option<String>,
        template: TemplateType,
        suffix: Option<String>,
    },
    InlineFlag {
        flag: String,
        template: TemplateType,
    },
}

#[derive(Debug)]
pub struct MatchResult {
    pub rule_index: usize,
    pub captures: HashMap<String, String>,
    pub subcommand_path: Vec<String>,
}
