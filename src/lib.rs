//! SkillScan: security scanner for Claude Skills.
//!
//! See the README for an overview. Top-level modules:
//!
//! - [`cli`] — command-line interface.
//! - [`model`] — domain types (`Skill`, `Finding`, `Severity`, `Report`).
//! - [`loaders`] — turn a path/archive/URL into a [`model::Skill`].
//! - [`engine`] — runs rules against a loaded skill.
//! - [`rules`] — built-in rule implementations.
//! - [`reporters`] — render a [`model::Report`] in various formats.

pub mod cli;
pub mod engine;
pub mod loaders;
pub mod model;
pub mod reporters;
pub mod rules;

/// Crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
