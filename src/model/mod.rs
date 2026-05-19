//! Domain model for SkillScan.
//!
//! These types are the contract between loaders, the engine, rules, and reporters.

pub mod finding;
pub mod frontmatter;
pub mod report;
pub mod severity;
pub mod skill;

pub use finding::{Finding, Span};
pub use frontmatter::Frontmatter;
pub use report::{Report, ScanStats};
pub use severity::Severity;
pub use skill::{FileKind, Skill, SkillFile};
