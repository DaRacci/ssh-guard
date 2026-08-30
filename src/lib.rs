#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]
#![deny(clippy::pedantic)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![feature(coverage_attribute)]

pub mod actions;
pub mod audit;
pub mod cli;
pub mod config;
pub mod engine;
pub mod errors;
pub mod help;
pub mod logging;
