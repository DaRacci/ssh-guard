mod flags;
mod matching;
pub(crate) mod parse;
pub(crate) mod types;
mod validate;

pub use matching::match_command;
pub use types::MatchResult;
