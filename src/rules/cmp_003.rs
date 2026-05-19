use std::path::PathBuf;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill};

const META: RuleMeta = RuleMeta {
    id: "SKILL-CMP-003",
    name: "Missing license declaration",
    severity: Severity::Low,
    category: Category::Compliance,
    default_remediation:
        "Declare a `license:` in the frontmatter, or ship a `LICENSE`/`COPYING` file at the skill root.",
};

#[derive(Debug)]
pub struct LicenseRule;

impl Rule for LicenseRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let has_field = skill
            .frontmatter
            .license
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        let has_file = skill.files.iter().any(|f| {
            f.rel_path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_uppercase())
                .is_some_and(|n| {
                    matches!(
                        n.as_str(),
                        "LICENSE" | "LICENSE.MD" | "LICENSE.TXT" | "COPYING"
                    )
                })
        });

        if has_field || has_file {
            return vec![];
        }
        vec![Finding {
            rule_id: META.id.into(),
            severity: META.severity,
            confidence: 100,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: "Skill declares no license (no frontmatter field and no LICENSE file).".into(),
            remediation: META.default_remediation.into(),
            references: vec![],
        }]
    }
}
