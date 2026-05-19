use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-002",
    name: "Missing version field",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "Add a `version:` field to the frontmatter so consumers can pin to a known revision.",
};

#[derive(Debug)]
pub struct VersionRule;

impl Rule for VersionRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        if skill
            .frontmatter
            .version
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 100,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: "Frontmatter is missing a `version` field.".into(),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
