use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-006",
    name: "SKILL.md is suspiciously large",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "A SKILL.md over 100 KiB is unusual; long single instruction files are harder to audit \
         and tend to bury intent. Split into multiple smaller skills or factor static data into \
         separate files.",
};

const SKILL_MD_SOFT_LIMIT_BYTES: u64 = 100 * 1024;

#[derive(Debug)]
pub struct LargeSkillMdRule;

impl Rule for LargeSkillMdRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        for f in &skill.files {
            if f.kind != FileKind::SkillMd {
                continue;
            }
            if f.size_bytes > SKILL_MD_SOFT_LIMIT_BYTES {
                return vec![Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 100,
                    file: PathBuf::from("SKILL.md"),
                    span: None,
                    message: format!(
                        "SKILL.md is {:.1} KiB; soft limit is {} KiB.",
                        f.size_bytes as f64 / 1024.0,
                        SKILL_MD_SOFT_LIMIT_BYTES / 1024
                    ),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                }];
            }
        }
        vec![]
    }
}
