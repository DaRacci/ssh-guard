use crate::errors::GuardError;
use crate::kinds::{ExecCtx, RuleKind};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct TailFile<'a> {
    pub(super) path_capture: &'a str,
    pub(super) lines_capture: Option<&'a str>,
    pub(super) default_lines: usize,
    pub(super) root_set: &'a str,
}

impl RuleKind for TailFile<'_> {
    fn name(&self) -> &'static str {
        "tail_file"
    }

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        let mut refs = vec![("path_capture", self.path_capture)];
        if let Some(lines_capture) = self.lines_capture {
            refs.push(("lines_capture", lines_capture));
        }
        refs
    }

    fn root_sets(&self) -> Vec<&str> {
        vec![self.root_set]
    }

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        let _ = self.default_lines;
        crate::actions::execute_tail_file(ctx.config, &ctx.rule.action, ctx.captures).map(|()| 0)
    }
}
