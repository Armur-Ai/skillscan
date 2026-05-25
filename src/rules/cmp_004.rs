use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-004",
    name: "Oversized skill bundle",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "Skills above 10 MiB are unusual. If the bundle contains large model artifacts or data \
         files, host them externally and reference at runtime instead of shipping inline.",
};

/// 10 MiB — well below the loader's hard cap (50 MiB), but worth a heads-up because skill
/// bundles tend to stay tiny.
const SOFT_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug)]
pub struct OversizedBundleRule;

impl Rule for OversizedBundleRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let total: u64 = skill.files.iter().map(|f| f.size_bytes).sum();
        if total <= SOFT_LIMIT_BYTES {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 100,
            file: PathBuf::from("."),
            span: None,
            message: format!(
                "Skill bundle is {:.1} MiB ({} files); soft limit is {} MiB.",
                total as f64 / (1024.0 * 1024.0),
                skill.files.len(),
                SOFT_LIMIT_BYTES / (1024 * 1024),
            ),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
