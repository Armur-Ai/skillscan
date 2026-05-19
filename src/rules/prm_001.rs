use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-001",
    name: "Unscoped Bash permission",
    severity: Severity::High,
    category: Category::Permissions,
    default_remediation:
        "Restrict `allowed-tools` to specific commands, e.g. `Bash(git status)` or `Bash(npm test)`.",
};

#[derive(Debug)]
pub struct BashWildcardRule;

impl Rule for BashWildcardRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let file = PathBuf::from("SKILL.md");
        let mut findings = Vec::new();

        for tool in &skill.frontmatter.allowed_tools {
            if is_unscoped_bash(tool) || tool.trim() == "*" {
                findings.push(Finding {
                    rule_id: META.id.into(),
                    severity: META.severity,
                    confidence: 95,
                    file: file.clone(),
                    span: None,
                    message: format!("`allowed-tools` grants unscoped shell via `{tool}`."),
                    remediation: META.default_remediation.into(),
                    references: vec![],
                });
            }
        }

        findings
    }
}

fn is_unscoped_bash(tool: &str) -> bool {
    let t = tool.trim();
    let lower = t.to_ascii_lowercase();
    if lower == "bash" || lower == "shell" {
        return true;
    }
    // Bash(*) / Bash(**) — wildcard inside the parenthesized scope means "any command".
    if let Some(inner) = lower
        .strip_prefix("bash(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let trimmed = inner.trim();
        return trimmed.is_empty() || trimmed == "*" || trimmed == "**";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_unscoped_bash;

    #[test]
    fn flags_wildcards() {
        assert!(is_unscoped_bash("Bash(*)"));
        assert!(is_unscoped_bash("bash(**)"));
        assert!(is_unscoped_bash("Bash"));
        assert!(is_unscoped_bash("  Bash( * )  "));
    }

    #[test]
    fn allows_scoped() {
        assert!(!is_unscoped_bash("Bash(git status)"));
        assert!(!is_unscoped_bash("Read"));
        assert!(!is_unscoped_bash("Bash(npm test)"));
    }
}
