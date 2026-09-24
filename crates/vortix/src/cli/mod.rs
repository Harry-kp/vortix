//! Command-line interface module.
//!
//! Provides argument parsing, structured output formatting, and CLI command handlers.

pub mod args;
pub mod commands;
#[doc(hidden)]
pub mod output;
pub(crate) mod profiles;
pub mod report;
pub mod status;
mod tunnel;
