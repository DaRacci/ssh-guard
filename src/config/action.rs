use serde::{Deserialize, Serialize};

use crate::config::duration::Duration;

#[coverage(off)]
const fn default_tail_lines() -> usize {
    200
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    Run {
        binary: String,

        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,

        #[serde(default)]
        timeout: Duration,
    },
    ReadFile {
        path_capture: String,

        root_set: String,
    },
    TailFile {
        path_capture: String,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        lines_capture: Option<String>,

        #[serde(default = "default_tail_lines")]
        default_lines: usize,

        root_set: String,
    },
    StatPath {
        path_capture: String,

        root_set: String,
    },
    ListDir {
        path_capture: String,

        root_set: String,
    },
    ShowHelp,
}
