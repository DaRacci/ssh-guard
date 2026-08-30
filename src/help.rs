use std::collections::HashMap;

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
        TemplateType::Union(_) => format!("<{}>", raw_union_member(t, contracts, opts)),
    };

    paint(PALETTE.template, &label, opts.colour)
}

#[must_use]
pub fn render_help(config: &Config, opts: &HelpOptions) -> String {
    let mut lines = vec!["Allowed commands:".to_string(), String::new()];

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

fn render_rule(config: &Config, rule: &Rule, opts: &HelpOptions) -> String {
    let Some(command) = rule.command_name() else {
        return String::new();
    };

    let flags = expand_flags(&config.flag_groups, &rule.flag_groups, &rule.flags);
    let mut parts = vec![paint(PALETTE.command, command, opts.colour)];

    let rendered_flags = render_args(&flags, &config.contracts, opts);
    if !rendered_flags.is_empty() {
        parts.push(rendered_flags);
    }

    let rendered_args = render_args(&rule.args, &config.contracts, opts);
    if !rendered_args.is_empty() {
        parts.push(rendered_args);
    }

    if opts.tree {
        let mut lines = vec![parts.join(" ")];
        for subcommand in &rule.subcommands {
            lines.push(render_subcommand(config, subcommand, 1, opts));
        }
        lines.join("\n")
    } else {
        for subcommand in &rule.subcommands {
            let rendered = render_subcommand(config, subcommand, 0, opts);
            if !rendered.is_empty() {
                parts.push(rendered);
            }
        }
        parts.join(" ")
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

    let rendered_flags = render_args(&flags, &config.contracts, opts);
    if !rendered_flags.is_empty() {
        parts.push(rendered_flags);
    }

    let rendered_args = render_args(&sub.args, &config.contracts, opts);
    if !rendered_args.is_empty() {
        parts.push(rendered_args);
    }

    if opts.tree {
        let mut lines = vec![format!("{}{}", "  ".repeat(depth), parts.join(" "))];
        for nested in &sub.subcommands {
            lines.push(render_subcommand(config, nested, depth + 1, opts));
        }
        lines.join("\n")
    } else {
        for nested in &sub.subcommands {
            let rendered = render_subcommand(config, nested, depth, opts);
            if !rendered.is_empty() {
                parts.push(rendered);
            }
        }
        parts.join(" ")
    }
}

fn render_args(
    args: &[String],
    contracts: &HashMap<String, Contract>,
    opts: &HelpOptions,
) -> String {
    args.iter()
        .map(|raw| match parse_arg_pattern(raw) {
            ArgPattern::Literal(literal) => paint(PALETTE.literal, &literal, opts.colour),
            ArgPattern::Template(template) => template_label(&template, contracts, opts),
            ArgPattern::TemplateContext {
                prefix,
                template,
                suffix,
            } => {
                let mut rendered = String::new();
                if let Some(prefix) = prefix {
                    rendered.push_str(&paint(PALETTE.dim, &prefix, opts.colour));
                }
                rendered.push_str(&template_label(&template, contracts, opts));
                if let Some(suffix) = suffix {
                    rendered.push_str(&paint(PALETTE.dim, &suffix, opts.colour));
                }
                rendered
            }
            ArgPattern::InlineFlag { flag, template } => {
                let rendered_flag = paint(PALETTE.literal, &flag, opts.colour);
                format!(
                    "{rendered_flag}={}",
                    template_label(&template, contracts, opts)
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
                binary: format!("/usr/bin/{command}"),
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
    fn test_paint_disabled() {
        assert_eq!(paint("\x1b[34m", "hello", false), "hello");
    }

    #[test]
    fn test_paint_enabled() {
        assert_eq!(paint("\x1b[34m", "hello", true), "\x1b[34mhello\x1b[0m");
    }

    #[test]
    fn test_render_compact_single_command() {
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
            out.contains("systemctl status <unit>.service"),
            "got: {out}"
        );
    }

    #[test]
    fn test_render_compact_multiple_commands() {
        let config = Config {
            rules: vec![
                run_rule(
                    "systemctl",
                    vec![sub("status", vec!["{unit}.service".into()])],
                    vec![],
                ),
                run_rule("journalctl", vec![sub("-n", vec!["{int}".into()])], vec![]),
            ],
            contracts: contracts(),
            ..Default::default()
        };
        let out = render_help(&config, &HelpOptions::default());
        assert!(
            out.contains("systemctl status <unit>.service"),
            "got: {out}"
        );
        assert!(out.contains("journalctl -n <int>"), "got: {out}");
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
