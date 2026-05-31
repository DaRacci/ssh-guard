use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TemplateType {
    String,
    Int,
    Any,
    ContractRef(String),
    Union(Vec<TemplateType>),
}

#[derive(Debug, Clone)]
pub(crate) enum ArgPattern {
    Literal(String),
    Template(TemplateType),
    /// Template with literal prefix and/or suffix, e.g. "--{unit}", "{unit}.service", "--{unit}.service"
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
