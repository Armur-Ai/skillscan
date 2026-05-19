use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-007",
    name: "Excessive allowed-tools count",
    severity: Severity::Medium,
    category: Category::Permissions,
    default_remediation:
        "Skill grants more than 15 tools. Pare down to the minimum required — every additional \
         tool widens the blast radius of a prompt-injection compromise.",
};

const TOOL_LIMIT: usize = 15;

#[derive(Debug)]
pub struct ExcessiveToolsRule;

impl Rule for ExcessiveToolsRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let n = skill.frontmatter.allowed_tools.len();
        if n <= TOOL_LIMIT {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 100,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: format!("Skill declares {n} tools (limit {TOOL_LIMIT})."),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
