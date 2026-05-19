use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-PRM-002",
    name: "Write/Edit permission targets a sensitive path",
    severity: Severity::High,
    category: Category::Permissions,
    default_remediation:
        "Narrow the path scope of Write/Edit/MultiEdit. System directories and credential dotfiles \
         should never be writable by a skill.",
};

/// Paths whose mention in a Write/Edit scope is almost always wrong.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/",
    "/usr/",
    "/var/",
    "/bin/",
    "/sbin/",
    "/boot/",
    "/root/",
    "~/.ssh",
    "/.ssh",
    "~/.aws",
    "/.aws",
    "~/.kube",
    "/.kube",
    "~/.gnupg",
    "/.gnupg",
    "~/.config/gcloud",
    "$HOME/.ssh",
    "$HOME/.aws",
];

const WRITE_PREFIXES: &[&str] = &["write(", "edit(", "multiedit(", "notebookedit("];

#[derive(Debug)]
pub struct SensitiveWritePathRule;

impl Rule for SensitiveWritePathRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &skill.frontmatter.allowed_tools {
            let lower = tool.trim().to_ascii_lowercase();
            if !WRITE_PREFIXES.iter().any(|p| lower.starts_with(p)) {
                continue;
            }
            for path in SENSITIVE_PATHS {
                if tool.contains(path) {
                    findings.push(Finding {
                        rule_id: META.id.into(),
                        severity: META.severity,
                        confidence: 90,
                        file: PathBuf::from("SKILL.md"),
                        span: None,
                        message: format!(
                            "Write/Edit scope targets sensitive path `{path}` in `{tool}`."
                        ),
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
