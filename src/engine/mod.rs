pub mod flags;
mod matching;
pub mod parse;
pub(crate) mod types;
mod validate;

pub use matching::match_command;
pub use types::MatchResult;
