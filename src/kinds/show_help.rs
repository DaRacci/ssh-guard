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
        crate::actions::execute_show_help(ctx.config);
        Ok(0)
    }
}
