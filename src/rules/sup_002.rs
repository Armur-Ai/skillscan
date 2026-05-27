use std::sync::LazyLock;

use regex::Regex;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill, Span};

const META: RuleMeta = RuleMeta {
    id: "SKILL-SUP-002",
    name: "Unpinned `pip install`",
    severity: Severity::Medium,
    category: Category::SupplyChain,
    default_remediation:
        "Pin the dependency version with `==<version>`, or install from a lockfile (`pip install \
         -r requirements.txt`). Unpinned installs at runtime mean the skill silently follows \
         whatever the index serves today.",
};

static PIP_INSTALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bpip3?\s+install\s+(?:[a-zA-Z][\w\-\.]*)").expect("static regex")
});

#[derive(Debug)]
pub struct UnpinnedPipRule;

impl Rule for UnpinnedPipRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &skill.files {
            if !matches!(
                file.kind,
                FileKind::Bash | FileKind::Markdown | FileKind::SkillMd | FileKind::Python
            ) {
                continue;
            }
            let Some(content) = &file.content else {
                continue;
            };

            let mut line_no = 0usize;
            for line in content.lines() {
                line_no += 1;
                for m in PIP_INSTALL.find_iter(line) {
                    if is_pinned_or_indirect(line, m.end()) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: META.id.into(),
                        severity: META.severity,
                        confidence: 75,
                        file: file.rel_path.clone(),
                        span: Some(Span {
                            line: line_no,
                            col: m.start() + 1,
                            end_line: line_no,
                            end_col: m.end() + 1,
                            byte_start: 0,
                            byte_end: 0,
                        }),
                        message: format!(
                            "Unpinned `pip install` at line {line_no}: `{}`",
                            m.as_str().trim()
                        ),
                        remediation: META.default_remediation.into(),
                        references: vec![],
                    });
                }
            }
        }
        findings
    }
}

/// Look at what follows the `pip install <name>` match to decide whether it's pinned or
/// references a requirements file (in which case the pinning lives elsewhere).
fn is_pinned_or_indirect(line: &str, end: usize) -> bool {
    // line includes the whole input; the match ended at `end`. Look at the next few chars.
    let rest = &line[end..];
    let trimmed = rest.trim_start();
    // Pinned with an operator immediately after the package name.
    if rest.starts_with("==")
        || rest.starts_with(">=")
        || rest.starts_with("<=")
        || rest.starts_with("~=")
        || rest.starts_with("!=")
    {
        return true;
    }
    // Requirements-file or editable install — pinning lives there.
    if trimmed.starts_with("-r ")
        || trimmed.starts_with("-e ")
        || trimmed.starts_with("--requirement")
    {
        return true;
    }
    // Hash-pinned or constraint file — the user is doing it right.
    if trimmed.contains("--hash=") || trimmed.contains("--constraint") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::PIP_INSTALL;

    #[test]
    fn matches_basic_install() {
        assert!(PIP_INSTALL.is_match("pip install requests"));
        assert!(PIP_INSTALL.is_match("pip3 install requests"));
    }

    #[test]
    fn skips_recognized_pin_in_post_check() {
        let line = "pip install requests==2.32.0";
        let m = PIP_INSTALL.find(line).unwrap();
        assert!(super::is_pinned_or_indirect(line, m.end()));
    }

    #[test]
    fn skips_requirements_file() {
        // The regex itself doesn't see `-r requirements.txt` as a package; the install_iter
        // would match `pip install -r` ... actually no, the regex requires a [a-zA-Z] start
        // after install, so `-r` doesn't match. Confirm.
        let line = "pip install -r requirements.txt";
        assert!(PIP_INSTALL.find(line).is_none());
    }
}
