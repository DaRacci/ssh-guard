use crate::errors::GuardError;
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct ListDir<'a> {
    pub(super) path_capture: &'a str,
    pub(super) root_set: &'a str,
}

impl RuleKind for ListDir<'_> {
    fn name(&self) -> &'static str {
        "list_dir"
    }

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        vec![("path_capture", self.path_capture)]
    }

    fn root_sets(&self) -> Vec<&str> {
        vec![self.root_set]
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        crate::actions::execute_list_dir(ctx.config, &ctx.rule.action, ctx.captures).map(|()| 0)
    }
}
