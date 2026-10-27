//! This module defines a Noop rule kind, primarily for testing purposes.

pub(crate) mod list_dir;
pub(crate) mod read_file;
pub(crate) mod run;
pub(crate) mod stat_path;
pub(crate) mod support;
pub(crate) mod tail_file;

use std::collections::HashMap;

use crate::config::action::Action;
use crate::config::rule::Rule;
use crate::config::Config;
use crate::errors::GuardError;

pub(crate) struct ExecCtx<'a> {
    pub(crate) config: &'a Config,
    pub(crate) rule: &'a Rule,
    pub(crate) subcommand_path: &'a [String],
    pub(crate) captures: &'a HashMap<String, String>,
    pub(crate) user_argv: &'a [String],
}

pub(crate) struct EnvCtx<'a> {
    pub(crate) rule: &'a Rule,
    pub(crate) scope: &'a str,
    pub(crate) index: usize,
}

pub(crate) trait RuleKind: Sync {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;

    fn capture_refs(&self) -> Vec<(&'static str, &str)> {
        Vec::new()
    }

    fn root_sets(&self) -> Vec<&str> {
        Vec::new()
    }

    fn visible_in_help(&self) -> bool {
        true
    }

    fn validate_env(&self, _ctx: &EnvCtx<'_>, _errors: &mut Vec<String>) {}

    fn execute(&self, ctx: &ExecCtx<'_>) -> Result<i32, GuardError>;
}

pub(crate) fn kind_for(action: &Action) -> Box<dyn RuleKind + '_> {
    match action {
        Action::Run {
            binary,
            args: _,
            timeout,
        } => Box::new(run::Run { binary, timeout }),
        Action::ReadFile {
            path_capture,
            root_set,
        } => Box::new(read_file::ReadFile {
            path_capture,
            root_set,
        }),
        Action::TailFile {
            path_capture,
            lines_capture,
            default_lines,
            root_set,
        } => Box::new(tail_file::TailFile {
            path_capture,
            lines_capture: lines_capture.as_deref(),
            default_lines: *default_lines,
            root_set,
        }),
        Action::StatPath {
            path_capture,
            root_set,
        } => Box::new(stat_path::StatPath {
            path_capture,
            root_set,
        }),
        Action::ListDir {
            path_capture,
            root_set,
        } => Box::new(list_dir::ListDir {
            path_capture,
            root_set,
        }),
        Action::Noop => Box::new(Noop),
    }
}

struct Noop;

impl RuleKind for Noop {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn visible_in_help(&self) -> bool {
        false
    }

    fn execute(&self, _ctx: &ExecCtx<'_>) -> Result<i32, GuardError> {
        Ok(0)
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::config::action::Action;
    use crate::config::duration::Duration;

    fn run_action() -> Action {
        Action::Run {
            binary: "/bin/true".into(),
            args: vec![],
            timeout: Duration::default(),
        }
    }

    #[test]
    fn test_kind_for_reports_serde_name() {
        assert_eq!(kind_for(&run_action()).name(), "run");
        assert_eq!(
            kind_for(&Action::ReadFile {
                path_capture: "p".into(),
                root_set: "roots".into(),
            })
            .name(),
            "read_file"
        );
    }

    #[test]
    fn test_read_file_reports_capture_refs_and_root_sets() {
        let action = Action::ReadFile {
            path_capture: "path".into(),
            root_set: "data".into(),
        };
        let kind = kind_for(&action);
        assert_eq!(kind.capture_refs(), vec![("path_capture", "path")]);
        assert_eq!(kind.root_sets(), vec!["data"]);
    }

    #[test]
    fn test_run_has_no_capture_refs_or_root_sets() {
        let action = run_action();
        let kind = kind_for(&action);
        assert!(kind.capture_refs().is_empty());
        assert!(kind.root_sets().is_empty());
    }
}
