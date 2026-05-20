use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub rules_run: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTiming {
    pub rule_id: String,
    /// Wall time in microseconds. Sub-millisecond rules are common, so we keep micros.
    pub duration_us: u64,
}

/// A scan result, ready to hand to a reporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// JSON schema version of this report shape. Bump on breaking changes.
    #[serde(rename = "schema_version")]
    pub schema_version: u32,
    pub skillscan_version: String,
    pub target: PathBuf,
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// SHA-256 of the loaded rule set, lowercase hex. Two runs with the same input and same
    /// `ruleset_hash` must produce identical findings.
    pub ruleset_hash: String,
    /// Per-rule wall time. Populated every scan; surfaced to the user only with `--profile`.
    #[serde(default)]
    pub rule_timings: Vec<RuleTiming>,
}

impl Report {
    #[must_use]
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    #[must_use]
    pub fn count_at_or_above(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .count()
    }
}

impl ScanStats {
    #[must_use]
    pub fn new(files_scanned: usize, rules_run: usize, duration: Duration) -> Self {
        Self {
            files_scanned,
            rules_run,
            duration_ms: duration.as_millis(),
        }
    }
}
