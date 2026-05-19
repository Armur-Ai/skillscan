use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-001",
    name: "Missing or too-short description",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "Add a `description:` field of at least 20 characters explaining what the skill does.",
};

const MIN_DESCRIPTION_LEN: usize = 20;

#[derive(Debug)]
pub struct DescriptionRule;

impl Rule for DescriptionRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let file = PathBuf::from("SKILL.md");
        match &skill.frontmatter.description {
            Some(d) if d.trim().chars().count() >= MIN_DESCRIPTION_LEN => vec![],
            Some(d) => vec![Finding {
                rule_id: META.id.into(),
                severity: META.severity,
                confidence: 100,
                file,
                span: None,
                message: format!(
                    "`description` is only {} chars; recommend at least {}.",
                    d.trim().chars().count(),
                    MIN_DESCRIPTION_LEN
                ),
                remediation: META.default_remediation.into(),
                references: vec![],
            }],
            None => vec![Finding {
                rule_id: META.id.into(),
                severity: META.severity,
                confidence: 100,
                file,
                span: None,
                message: "Frontmatter is missing a `description` field.".into(),
                remediation: META.default_remediation.into(),
                references: vec![],
            }],
        }
    }
}
