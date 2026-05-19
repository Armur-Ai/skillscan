use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Severity;

/// A byte/line range inside a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub line: usize,
    pub col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub byte_start: usize,
    pub byte_end: usize,
}

/// A single finding produced by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    /// 0..=100. Higher means the rule is more sure of the hit.
    pub confidence: u8,
    /// Path of the offending file, relative to the skill root.
    pub file: PathBuf,
    pub span: Option<Span>,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<String>,
}
