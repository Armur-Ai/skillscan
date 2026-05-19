//! Loaders turn a target (directory, archive, git URL, http URL) into a `Skill`.
//!
//! Phase 1 lands `DirectoryLoader`. Phase 3 adds archive/git/url loaders gated behind
//! `--allow-network`.

pub mod directory;

pub use directory::DirectoryLoader;
