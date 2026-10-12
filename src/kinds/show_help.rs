use crate::errors::GuardError;
use crate::kinds::{ExecCtx, RuleKind};

pub(super) struct ShowHelp;

impl RuleKind for ShowHelp {
    fn name(&self) -> &'static str {
        "show_help"
    }

    fn visible_in_help(&self) -> bool {
        false
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        print!("{}", ctx.config.global.help_text);
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::global::Global;
    use crate::config::rule::Rule;
    use crate::config::Config;
    use crate::kinds::{ExecCtx, RuleKind};

    fn rule() -> Rule {
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
        }
    }

    #[test]
    fn test_execute_show_help_prints_help_text() {
        let config = Config {
            global: Global {
                help_text: r#"Available commands:
                  status
                  show
                "#
                .into(),
                ..Global::default()
            },
            ..Default::default()
        };
        let rule = rule();
        let captures = HashMap::new();
        let ctx = ExecCtx {
            config: &config,
            rule: &rule,
            subcommand_path: &[],
            captures: &captures,
            user_argv: &[],
        };

        assert_eq!(ShowHelp.execute(&ctx).unwrap(), 0);
    }
}
