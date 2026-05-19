use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-004",
    name: "Unscoped WebFetch or WebSearch permission",
    severity: Severity::Medium,
    category: Category::Permissions,
    default_remediation:
        "Restrict WebFetch/WebSearch to a host allowlist, e.g. `WebFetch(docs.example.com)`. \
         Unscoped network access is a common exfiltration channel.",
};

#[derive(Debug)]
pub struct UnscopedWebFetchRule;

impl Rule for UnscopedWebFetchRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &skill.frontmatter.allowed_tools {
            let lower = tool.trim().to_ascii_lowercase();
            let is_web = lower == "webfetch" || lower == "websearch";
            let is_wildcard_paren = (lower.starts_with("webfetch(")
                || lower.starts_with("websearch("))
                && (lower.contains("(*)") || lower.contains("(**)") || lower.ends_with("()"));

            if is_web || is_wildcard_paren {
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: PathBuf::from("SKILL.md"),
                    span: None,
                    message: format!("Unscoped web access via `{tool}`."),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            }
        }
        findings
    }
}
