use crate::errors::GuardError;
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct StatPath<'a> {
    pub(super) path_capture: &'a str,
    pub(super) root_set: &'a str,
}

impl RuleKind for StatPath<'_> {
    fn name(&self) -> &'static str {
        "stat_path"
    }

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        vec![("path_capture", self.path_capture)]
    }

    fn root_sets(&self) -> Vec<&str> {
        vec![self.root_set]
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        crate::actions::execute_stat_path(ctx.config, &ctx.rule.action, ctx.captures).map(|()| 0)
    }
}
