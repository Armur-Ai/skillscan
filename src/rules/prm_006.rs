use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-006",
    name: "allowed-tools not declared",
    severity: Severity::Medium,
    category: Category::Permissions,
    default_remediation:
        "Declare an explicit `allowed-tools:` list. An empty or missing list grants whatever the \
         host environment provides — often more than intended.",
};

#[derive(Debug)]
pub struct AllowedToolsMissingRule;

impl Rule for AllowedToolsMissingRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        if !skill.frontmatter.allowed_tools.is_empty() {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 90,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: "Frontmatter has no `allowed-tools:` list; tool surface is implicit.".into(),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
