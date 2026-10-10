use std::collections::HashMap;
use std::fmt::Write;

use crate::config::Config;
use crate::config::action::Action;
use crate::config::contract::Contract;
use crate::config::rule::Rule;
use crate::config::subcommand::Subcommand;
use crate::engine::flags::expand_flags;
use crate::engine::parse::parse_arg_pattern;
use crate::engine::types::{ArgPattern, TemplateType};

#[derive(Default)]
pub struct HelpOptions {
    pub tree: bool,
    pub verbose: bool,
    pub colour: bool,
}

pub struct ColourPalette {
    pub command: &'static str,
    pub subcommand: &'static str,
    pub literal: &'static str,
    pub template: &'static str,
    pub dim: &'static str,
    pub reset: &'static str,
}

pub const PALETTE: ColourPalette = ColourPalette {
    command: "\x1b[1m",
    subcommand: "\x1b[32m",
    literal: "\x1b[36m",
    template: "\x1b[34m",
    dim: "\x1b[2m",
    reset: "\x1b[0m",
};

/// Wrap `text` in an ANSI colour when enabled, else return it unchanged.
fn paint(colour: &str, text: &str, enabled: bool) -> String {
    if enabled {
        format!("{colour}{text}{}", PALETTE.reset)
    } else {
        text.to_string()
    }
}

fn template_label(
    t: &TemplateType,
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
) -> String {
    fn raw_union_member(
        t: &TemplateType,
        contracts: &HashMap<String, Contract>,
        opts: &HelpOptions,
    ) -> String {
        match t {
            TemplateType::String => "string".to_string(),
            TemplateType::Int => "int".to_string(),
            TemplateType::Any => "any".to_string(),
            TemplateType::ContractRef(name) => {
                if !opts.verbose {
                    return name.clone();
                }
                match contracts.get(name) {
                    Some(Contract::IntRange { min, max }) => format!("{name}:{min}-{max}"),
                    Some(Contract::StringLen { min, max }) => {
                        format!("{name}:{min}..{max} chars")
                    }
                    Some(Contract::Enum { values }) => format!("{name}: {}", values.join("|")),
                    None => name.clone(),
                }
            }
            TemplateType::Named { name, inner } => {
                if !opts.verbose {
                    return name.clone();
                }
                format!("{name}:{}", raw_union_member(inner, contracts, opts))
            }
            TemplateType::Union(types) => types
                .iter()
                .map(|template| raw_union_member(template, contracts, opts))
                .collect::<Vec<_>>()
                .join("|"),
        }
    }

    let label = match t {
        TemplateType::String => "<string>".to_string(),
        TemplateType::Int => "<int>".to_string(),
        TemplateType::Any => "<any>".to_string(),
        TemplateType::ContractRef(name) => {
            if opts.verbose {
                match contracts.get(name) {
                    Some(Contract::IntRange { min, max }) => format!("<{name}:{min}-{max}>"),
                    Some(Contract::StringLen { min, max }) => {
                        format!("<{name}:{min}..{max} chars>")
                    }
                    Some(Contract::Enum { values }) => format!("<{name}: {}>", values.join("|")),
                    None => format!("<{name}>"),
                }
            } else {
                format!("<{name}>")
            }
        }
        TemplateType::Named { name, inner } => {
            if opts.verbose {
                format!("<{name}:{}>", raw_union_member(inner, contracts, opts))
            } else {
                format!("<{name}>")
            }
        }
        TemplateType::Union(_) => format!("<{}>", raw_union_member(t, contracts, opts)),
    };

    paint(PALETTE.template, &label, opts.colour)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValueDetail {
    plain_token: String,
    display_token: String,
    description: String,
}

#[must_use]
pub fn render_help(config: &Config, opts: &HelpOptions) -> String {
    let mut lines = render_legend(opts);
    let details = collect_value_details(config, opts);

    if !details.is_empty() {
        lines.push(String::new());
        lines.push("Value details:".to_string());
        lines.push(String::new());
        for detail in details {
            lines.push(format!(
                "  {}  {}",
                detail.display_token, detail.description
            ));
        }
    }

    lines.push(String::new());
    lines.push("Allowed commands:".to_string());
    lines.push(String::new());

    for rule in &config.rules {
        if matches!(rule.action, Action::ShowHelp) {
            continue;
        }

        let rendered = render_rule(config, rule, opts);
        if !rendered.is_empty() {
            lines.push(rendered);
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

fn render_legend(opts: &HelpOptions) -> Vec<String> {
    vec![
        "Legend:".to_string(),
        String::new(),
        format!(
            "  {}  top-level command",
            paint(PALETTE.command, "command", opts.colour)
        ),
        format!(
            "  {}  nested subcommand",
            paint(PALETTE.subcommand, "subcommand", opts.colour)
        ),
        format!(
            "  {}  fixed token you type exactly",
            paint(PALETTE.literal, "literal", opts.colour)
        ),
        format!(
            "  {}  optional flag",
            wrap_optional(&paint(PALETTE.literal, "--flag", opts.colour), opts)
        ),
        format!(
            "  {}  value you supply",
            template_label(
                &TemplateType::Named {
                    name: "value".to_string(),
                    inner: Box::new(TemplateType::String),
                },
                &HashMap::new(),
                opts
            )
        ),
    ]
}

fn render_rule(config: &Config, rule: &Rule, opts: &HelpOptions) -> String {
    let Some(command) = rule.command_name() else {
        return String::new();
    };

    let flags = expand_flags(&config.flag_groups, &rule.flag_groups, &rule.flags);
    let mut prefix_parts = vec![paint(PALETTE.command, command, opts.colour)];

    let rendered_flags = render_optional_args(&flags, &config.contracts, opts);
    if !rendered_flags.is_empty() {
        prefix_parts.push(rendered_flags);
    }

    let rendered_args = render_args(&rule.args, &config.contracts, opts);
    if !rendered_args.is_empty() {
        prefix_parts.push(rendered_args);
    }

    if rule.subcommands.is_empty() {
        prefix_parts.join(" ")
    } else {
        let mut lines = vec![prefix_parts.join(" ")];
        for subcommand in &rule.subcommands {
            lines.push(render_subcommand(config, subcommand, 1, opts));
        }
        lines.join("\n")
    }
}

fn render_subcommand(
    config: &Config,
    sub: &Subcommand,
    depth: usize,
    opts: &HelpOptions,
) -> String {
    let flags = expand_flags(&config.flag_groups, &sub.flag_groups, &sub.flags);
    let mut parts = vec![paint(PALETTE.subcommand, &sub.name, opts.colour)];

    let rendered_flags = render_optional_args(&flags, &config.contracts, opts);
    if !rendered_flags.is_empty() {
        parts.push(rendered_flags);
    }

    let rendered_args = render_args(&sub.args, &config.contracts, opts);
    if !rendered_args.is_empty() {
        parts.push(rendered_args);
    }

    let mut lines = vec![format!("{}{}", "  ".repeat(depth), parts.join(" "))];
    for nested in &sub.subcommands {
        lines.push(render_subcommand(config, nested, depth + 1, opts));
    }
    lines.join("\n")
}

fn render_optional_args(
    args: &[String],
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
) -> String {
    args.iter()
        .map(|raw| wrap_optional(&render_raw_arg(raw, contracts, opts), opts))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_args(
    args: &[String],
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
) -> String {
    args.iter()
        .map(|raw| render_raw_arg(raw, contracts, opts))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_raw_arg(raw: &str, contracts: &HashMap<String, Contract>, opts: &HelpOptions) -> String {
    render_pattern(&parse_arg_pattern(raw), contracts, opts)
}

fn render_pattern(
    pattern: &ArgPattern,
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
) -> String {
    match pattern {
        ArgPattern::Literal(literal) => paint(PALETTE.literal, literal, opts.colour),
        ArgPattern::Template(template) => template_label(template, contracts, opts),
        ArgPattern::TemplateContext {
            prefix,
            template,
            suffix,
        } => {
            let mut rendered = String::new();
            if let Some(prefix) = prefix {
                rendered.push_str(&paint(PALETTE.dim, prefix, opts.colour));
            }
            rendered.push_str(&template_label(template, contracts, opts));
            if let Some(suffix) = suffix {
                rendered.push_str(&paint(PALETTE.dim, suffix, opts.colour));
            }
            rendered
        }
        ArgPattern::InlineFlag { flag, template } => {
            let rendered_flag = paint(PALETTE.literal, flag, opts.colour);
            let equals = paint(PALETTE.dim, "=", opts.colour);
            format!(
                "{rendered_flag}{equals}{}",
                template_label(template, contracts, opts)
            )
        }
    }
}

fn wrap_optional(rendered: &str, opts: &HelpOptions) -> String {
    let open = paint(PALETTE.dim, "[", opts.colour);
    let close = paint(PALETTE.dim, "]", opts.colour);
    format!("{open}{rendered}{close}")
}

fn collect_value_details(config: &Config, opts: &HelpOptions) -> Vec<ValueDetail> {
    let mut details = Vec::new();

    for rule in &config.rules {
        if matches!(rule.action, Action::ShowHelp) {
            continue;
        }
        let flags = expand_flags(&config.flag_groups, &rule.flag_groups, &rule.flags);
        collect_details_for_tokens(&flags, true, &config.contracts, opts, &mut details);
        collect_details_for_tokens(&rule.args, false, &config.contracts, opts, &mut details);
        for sub in &rule.subcommands {
            collect_subcommand_value_details(config, sub, opts, &mut details);
        }
    }

    details
}

fn collect_subcommand_value_details(
    config: &Config,
    sub: &Subcommand,
    opts: &HelpOptions,
    details: &mut Vec<ValueDetail>,
) {
    let flags = expand_flags(&config.flag_groups, &sub.flag_groups, &sub.flags);
    collect_details_for_tokens(&flags, true, &config.contracts, opts, details);
    collect_details_for_tokens(&sub.args, false, &config.contracts, opts, details);

    for nested in &sub.subcommands {
        collect_subcommand_value_details(config, nested, opts, details);
    }
}

fn collect_details_for_tokens(
    raw_tokens: &[String],
    optional: bool,
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
    details: &mut Vec<ValueDetail>,
) {
    let plain_opts = HelpOptions {
        tree: opts.tree,
        verbose: opts.verbose,
        colour: false,
    };

    for raw in raw_tokens {
        let pattern = parse_arg_pattern(raw);
        let description = detail_description(&pattern, contracts);
        if let Some(description) = description {
            let plain_token = if optional {
                wrap_optional(
                    &render_pattern(&pattern, contracts, &plain_opts),
                    &plain_opts,
                )
            } else {
                render_pattern(&pattern, contracts, &plain_opts)
            };
            if details.iter().any(|detail| {
                detail.plain_token == plain_token && detail.description == description
            }) {
                continue;
            }

            let display_token = if optional {
                wrap_optional(&render_pattern(&pattern, contracts, opts), opts)
            } else {
                render_pattern(&pattern, contracts, opts)
            };
            details.push(ValueDetail {
                plain_token,
                display_token,
                description,
            });
        }
    }
}

fn detail_description(
    pattern: &ArgPattern,
    contracts: &HashMap<String, Contract>,
) -> Option<String> {
    match pattern {
        ArgPattern::Literal(_) => None,
        ArgPattern::Template(template) | ArgPattern::InlineFlag { template, .. } => {
            Some(describe_template(template, contracts))
        }
        ArgPattern::TemplateContext {
            prefix,
            template,
            suffix,
        } => {
            let mut desc = describe_template(template, contracts);
            if let Some(prefix) = prefix {
                let _ = write!(desc, "; literal prefix '{prefix}'");
            }
            if let Some(suffix) = suffix {
                let _ = write!(desc, "; literal suffix '{suffix}'");
            }
            Some(desc)
        }
    }
}

fn describe_template(template: &TemplateType, contracts: &HashMap<String, Contract>) -> String {
    match template {
        TemplateType::String => "text value".to_string(),
        TemplateType::Int => "integer".to_string(),
        TemplateType::Any => "any value".to_string(),
        TemplateType::ContractRef(name) => match contracts.get(name) {
            Some(Contract::IntRange { min, max }) => format!("integer {min}..{max}"),
            Some(Contract::StringLen { min, max }) => format!("text {min}..{max} chars"),
            Some(Contract::Enum { values }) => format!("one of: {}", values.join(" | ")),
            None => format!("value matching contract '{name}'"),
        },
        TemplateType::Named { inner, .. } => describe_template(inner, contracts),
        TemplateType::Union(types) => format!(
            "one of: {}",
            types
                .iter()
                .map(|part| describe_template(part, contracts))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::rule::Rule;
    use crate::config::subcommand::Subcommand;

    fn contracts() -> HashMap<String, Contract> {
        let mut m = HashMap::new();
        m.insert(
            "port".into(),
            Contract::IntRange {
                min: 1024,
                max: 65535,
            },
        );
        m.insert(
            "unit".into(),
            Contract::Enum {
                values: vec!["sshd".into(), "nginx".into()],
            },
        );
        m
    }

    fn opts(verbose: bool) -> HelpOptions {
        HelpOptions {
            tree: false,
            verbose,
            colour: false,
        }
    }

    fn run_rule(command: &str, subcommands: Vec<Subcommand>, args: Vec<String>) -> Rule {
        Rule {
            action: Action::Run {
                binary: format!("/opt/test/bin/{command}"),
                args: vec![],
                timeout: crate::config::duration::Duration::default(),
            },
            command: Some(command.to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags: vec![],
            args,
            pre_args: vec![],
            subcommands,
        }
    }

    fn sub(name: &str, args: Vec<String>) -> Subcommand {
        Subcommand {
            name: name.to_string(),
            arg_style: None,
            flag_groups: vec![],
            flags: vec![],
            args,
            pre_args: vec![],
            subcommands: vec![],
        }
    }

    fn run_rule_with_flags(command: &str, flags: Vec<String>) -> Rule {
        Rule {
            action: Action::Run {
                binary: format!("/opt/test/bin/{command}"),
                args: vec![],
                timeout: crate::config::duration::Duration::default(),
            },
            command: Some(command.to_string()),
            implicit_symlinks: true,
            arg_style: ArgStyle::GnuLong,
            flag_groups: vec![],
            flags,
            args: vec![],
            pre_args: vec![],
            subcommands: vec![],
        }
    }

    #[test]
    fn test_label_builtins() {
        let c = HashMap::new();
        assert_eq!(
            template_label(
                &crate::engine::types::TemplateType::String,
                &c,
                &opts(false)
            ),
            "<string>"
        );
        assert_eq!(
            template_label(&crate::engine::types::TemplateType::Int, &c, &opts(false)),
            "<int>"
        );
        assert_eq!(
            template_label(&crate::engine::types::TemplateType::Any, &c, &opts(false)),
            "<any>"
        );
    }

    #[test]
    fn test_label_contract_plain() {
        let c = contracts();
        assert_eq!(
            template_label(
                &crate::engine::types::TemplateType::ContractRef("port".into()),
                &c,
                &opts(false)
            ),
            "<port>"
        );
    }

    #[test]
    fn test_label_contract_verbose() {
        let c = contracts();
        assert_eq!(
            template_label(
                &crate::engine::types::TemplateType::ContractRef("port".into()),
                &c,
                &opts(true)
            ),
            "<port:1024-65535>"
        );
        assert_eq!(
            template_label(
                &crate::engine::types::TemplateType::ContractRef("unit".into()),
                &c,
                &opts(true)
            ),
            "<unit: sshd|nginx>"
        );
    }

    #[test]
    fn test_label_union() {
        let c = HashMap::new();
        let u = crate::engine::types::TemplateType::Union(vec![
            crate::engine::types::TemplateType::Int,
            crate::engine::types::TemplateType::String,
        ]);
        assert_eq!(template_label(&u, &c, &opts(false)), "<int|string>");
    }

    #[test]
    fn test_label_unknown_contract_verbose() {
        let c = HashMap::new();
        assert_eq!(
            template_label(
                &crate::engine::types::TemplateType::ContractRef("nope".into()),
                &c,
                &opts(true)
            ),
            "<nope>"
        );
    }

    #[test]
    fn test_label_named_nonverbose() {
        let c = HashMap::new();
        let named = crate::engine::types::TemplateType::Named {
            name: "path".into(),
            inner: Box::new(crate::engine::types::TemplateType::String),
        };
        assert_eq!(template_label(&named, &c, &opts(false)), "<path>");
    }

    #[test]
    fn test_label_named_verbose() {
        let c = HashMap::new();
        let named = crate::engine::types::TemplateType::Named {
            name: "path".into(),
            inner: Box::new(crate::engine::types::TemplateType::String),
        };
        assert_eq!(template_label(&named, &c, &opts(true)), "<path:string>");
    }

    #[test]
    fn test_label_named_inner_union() {
        let c = HashMap::new();
        let named = crate::engine::types::TemplateType::Named {
            name: "x".into(),
            inner: Box::new(crate::engine::types::TemplateType::Union(vec![
                crate::engine::types::TemplateType::Int,
                crate::engine::types::TemplateType::String,
            ])),
        };
        assert_eq!(template_label(&named, &c, &opts(false)), "<x>");
        assert_eq!(template_label(&named, &c, &opts(true)), "<x:int|string>");
    }

    #[test]
    fn test_paint_disabled() {
        assert_eq!(paint("\x1b[34m", "hello", false), "hello");
    }

    #[test]
    fn test_paint_enabled() {
        assert_eq!(paint("\x1b[34m", "hello", true), "\x1b[34mhello\x1b[0m");
    }

    #[test]
    fn test_render_default_single_command_with_subcommands() {
        let config = Config {
            rules: vec![run_rule(
                "systemctl",
                vec![sub("status", vec!["{unit}.service".into()])],
                vec![],
            )],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(
            out.contains("systemctl\n  status <unit>.service"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_default_multiple_commands() {
        let config = Config {
            rules: vec![
                run_rule(
                    "systemctl",
                    vec![sub("status", vec!["{unit}.service".into()])],
                    vec![],
                ),
                run_rule(
                    "journalctl",
                    vec![],
                    vec!["-n={int}".into(), "--since".into()],
                ),
            ],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(
            out.contains("systemctl\n  status <unit>.service"),
            "got: {out}"
        );
        assert!(out.contains("journalctl -n=<int> --since"), "got: {out}");
    }

    #[test]
    fn test_render_default_subcommands_indented() {
        let config = Config {
            rules: vec![run_rule(
                "systemctl",
                vec![
                    sub("status", vec!["{unit}.service".into()]),
                    sub("show", vec!["{unit}".into()]),
                ],
                vec![],
            )],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(
            out.contains("systemctl\n  status <unit>.service\n  show <unit>"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_tree_nested() {
        let config = Config {
            rules: vec![run_rule(
                "git",
                vec![sub("log", vec!["--oneline".into()])],
                vec![],
            )],
            ..Default::default()
        };
        let out = render_help(
            &config,
            &HelpOptions {
                tree: true,
                verbose: false,
                colour: false,
            },
        );
        assert!(out.contains("git"), "got: {out}");
        assert!(out.contains("log --oneline"), "got: {out}");
    }

    #[test]
    fn test_render_skips_show_help() {
        let config = Config {
            rules: vec![
                run_rule("systemctl", vec![], vec![]),
                Rule {
                    action: Action::ShowHelp,
                    command: Some("help".into()),
                    implicit_symlinks: true,
                    arg_style: ArgStyle::GnuLong,
                    flag_groups: vec![],
                    flags: vec![],
                    args: vec![],
                    pre_args: vec![],
                    subcommands: vec![],
                },
            ],
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(out.contains("systemctl"), "got: {out}");
        assert!(
            !out.contains("help"),
            "show_help rule should be skipped, got: {out}"
        );
    }

    #[test]
    fn test_render_inline_flag() {
        let config = Config {
            rules: vec![run_rule("git", vec![], vec!["--depth={int}".into()])],
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(out.contains("--depth=<int>"), "got: {out}");
    }

    #[test]
    fn test_render_empty_rules() {
        let config = Config::default();
        let out = render_help(&config, &HelpOptions::default());
        assert!(out.contains("Allowed commands"), "got: {out}");
    }

    #[test]
    fn test_render_includes_legend_and_value_details() {
        let config = Config {
            rules: vec![
                run_rule(
                    "systemctl",
                    vec![
                        sub("status", vec!["{unit}.service".into()]),
                        sub("show", vec!["{unit}".into()]),
                    ],
                    vec![],
                ),
                run_rule_with_flags(
                    "journalctl",
                    vec!["--since".into(), "-n={int}".into(), "--no-pager".into()],
                ),
            ],
            contracts: contracts(),
            ..Default::default()
        };

        let out = render_help(&config, &HelpOptions::default());
        let legend_idx = out.find("Legend:").expect("legend missing");
        let commands_idx = out
            .find("Allowed commands:")
            .expect("allowed commands heading missing");

        assert!(legend_idx < commands_idx, "got: {out}");
        assert!(out.contains("Value details:"), "got: {out}");
        assert!(out.contains("<unit>.service"), "got: {out}");
        assert!(out.contains("one of: sshd | nginx"), "got: {out}");
        assert!(out.contains("literal suffix '.service'"), "got: {out}");
    }

    #[test]
    fn test_render_brackets_optional_flags_when_not_coloured() {
        let config = Config {
            rules: vec![run_rule_with_flags(
                "journalctl",
                vec!["--since".into(), "-n={int}".into(), "--no-pager".into()],
            )],
            ..Default::default()
        };

        let out = render_help(&config, &HelpOptions::default());
        assert!(
            out.contains("journalctl [--since] [-n=<int>] [--no-pager]"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_colour_legend_uses_painted_examples() {
        let config = Config {
            rules: vec![run_rule(
                "systemctl",
                vec![sub("status", vec!["{unit}".into()])],
                vec![],
            )],
            ..Default::default()
        };

        let out = render_help(
            &config,
            &HelpOptions {
                tree: false,
                verbose: false,
                colour: true,
            },
        );

        assert!(out.contains("Legend:"), "got: {out}");
        assert!(
            out.contains("\x1b[1mcommand\x1b[0m") || out.contains("\x1b[1msystemctl\x1b[0m"),
            "got: {out}"
        );
        assert!(
            out.contains("\x1b[34m<value>\x1b[0m") || out.contains("\x1b[34m<unit>\x1b[0m"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_value_details_include_top_level_flag_groups() {
        let mut flag_groups = HashMap::new();
        flag_groups.insert("service-flags".into(), vec!["--port={port}".into()]);

        let config = Config {
            rules: vec![Rule {
                action: Action::Run {
                    binary: "/opt/test/bin/journalctl".into(),
                    args: vec![],
                    timeout: crate::config::duration::Duration::default(),
                },
                command: Some("journalctl".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["service-flags".into()],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            }],
            contracts: contracts(),
            flag_groups,
            ..Default::default()
        };

        let out = render_help(&config, &HelpOptions::default());
        assert!(out.contains("[--port=<port>]"), "got: {out}");
        assert!(out.contains("integer 1024..65535"), "got: {out}");
    }

    #[test]
    fn test_render_inline_flag_equals_dimmed_when_coloured() {
        let config = Config {
            rules: vec![run_rule("journalctl", vec![], vec!["-n={int}".into()])],
            ..Default::default()
        };
        let out = render_help(
            &config,
            &HelpOptions {
                tree: false,
                verbose: false,
                colour: true,
            },
        );
        assert!(
            out.contains("\x1b[36m-n\x1b[0m\x1b[2m=\x1b[0m\x1b[34m<int>\x1b[0m"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_colour_contract_blue() {
        let config = Config {
            rules: vec![run_rule(
                "systemctl",
                vec![sub("status", vec!["{unit}.service".into()])],
                vec![],
            )],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(
            &config,
            &HelpOptions {
                tree: false,
                verbose: false,
                colour: true,
            },
        );
        assert!(
            out.contains("\x1b[34m<unit>\x1b[0m"),
            "template should be blue, got: {out}"
        );
    }

    #[test]
    fn test_render_colour_command_bold() {
        let config = Config {
            rules: vec![run_rule("systemctl", vec![], vec![])],
            ..Default::default()
        };
        let out = render_help(
            &config,
            &HelpOptions {
                tree: false,
                verbose: false,
                colour: true,
            },
        );
        assert!(
            out.contains("\x1b[1msystemctl\x1b[0m"),
            "command should be bold, got: {out}"
        );
    }

    #[test]
    fn test_render_colour_subcommand_green() {
        let config = Config {
            rules: vec![run_rule("systemctl", vec![sub("status", vec![])], vec![])],
            ..Default::default()
        };
        let out = render_help(
            &config,
            &HelpOptions {
                tree: false,
                verbose: false,
                colour: true,
            },
        );
        assert!(
            out.contains("\x1b[32mstatus\x1b[0m"),
            "subcommand should be green, got: {out}"
        );
    }

    #[test]
    fn test_render_no_colour_when_disabled() {
        let config = Config {
            rules: vec![run_rule(
                "systemctl",
                vec![sub("status", vec!["{unit}.service".into()])],
                vec![],
            )],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(
            !out.contains("\x1b["),
            "no ANSI codes when colour disabled, got: {out}"
        );
    }
}
