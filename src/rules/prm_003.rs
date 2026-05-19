use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-003",
    name: "Read permission targets sensitive dotfiles",
    severity: Severity::High,
    category: Category::Permissions,
    default_remediation:
        "Read scope should not include credential dotfiles. If you genuinely need a value from \
         one, accept it via an environment variable instead.",
};

const SENSITIVE_READS: &[&str] = &[
    "~/.ssh",
    "/.ssh",
    "~/.aws",
    "/.aws",
    "~/.kube",
    "/.kube",
    "~/.gnupg",
    "/.gnupg",
    "~/.config/gcloud",
    "~/.netrc",
    "/.netrc",
    "$HOME/.ssh",
    "$HOME/.aws",
    "/etc/shadow",
    "/etc/sudoers",
];

#[derive(Debug)]
pub struct SensitiveReadPathRule;

impl Rule for SensitiveReadPathRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &skill.frontmatter.allowed_tools {
            let lower = tool.trim().to_ascii_lowercase();
            if !lower.starts_with("read(") {
                continue;
            }
            for path in SENSITIVE_READS {
                if tool.contains(path) {
                    findings.push(Finding {
                        rule_id: META.id.into(),
                        severity: META.severity,
                        confidence: 90,
                        file: PathBuf::from("SKILL.md"),
                        span: None,
                        message: format!("Read scope targets sensitive path `{path}` in `{tool}`."),
                        remediation: META.default_remediation.into(),
                        references: vec![],
                    });
                    break;
                }
            }
        }
        findings
    }
}
