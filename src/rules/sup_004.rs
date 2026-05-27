use std::sync::LazyLock;

use regex::Regex;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{FileKind, Finding, Severity, Skill, Span};

const META: RuleMeta = RuleMeta {
    id: "SKILL-SUP-004",
    name: "Imports or installs a known PyPI typosquat",
    severity: Severity::Critical,
    category: Category::SupplyChain,
    default_remediation:
        "This is a known typosquat of a legitimate PyPI package. Almost certainly malicious. \
         Switch to the canonical name and audit any code that touched the squat package.",
};

/// Hand-curated list of well-known typosquats and their legitimate counterparts. Each entry is
/// `(squat, intended)`. Extend conservatively — false positives on this rule are reputation
/// damage to a legitimate package.
const TYPOSQUATS: &[(&str, &str)] = &[
    ("urllib", "urllib3"),
    ("python-sqlite", "pysqlite3"),
    ("djano", "django"),
    ("flsk", "flask"),
    ("requesst", "requests"),
    ("reuqests", "requests"),
    ("tensorfow", "tensorflow"),
    ("tornadoo", "tornado"),
    ("beatufulsoup4", "beautifulsoup4"),
    ("beatifulsoup4", "beautifulsoup4"),
    ("boto33", "boto3"),
    ("numppy", "numpy"),
    ("pandasss", "pandas"),
    ("matplotllib", "matplotlib"),
    ("scipi", "scipy"),
    ("cryptograpy", "cryptography"),
    ("pyyaaml", "pyyaml"),
    ("pillooow", "pillow"),
    ("pythonn-dateutil", "python-dateutil"),
    ("setupttools", "setuptools"),
];

static PIP_INSTALL_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bpip3?\s+install\s+(?:--[\w-]+\s+\S*\s+)*([a-zA-Z][\w\-\.]+)").expect("regex")
});

static PY_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:from|import)\s+([a-zA-Z][\w]+)").expect("regex"));

#[derive(Debug)]
pub struct PypiTyposquatRule;

impl Rule for PypiTyposquatRule {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &skill.files {
            let Some(content) = &file.content else {
                continue;
            };

            let mut line_no = 0usize;
            for line in content.lines() {
                line_no += 1;

                // pip install <pkg> in scripts / docs
                if matches!(
                    file.kind,
                    FileKind::Bash | FileKind::Markdown | FileKind::SkillMd | FileKind::Python
                ) {
                    if let Some(cap) = PIP_INSTALL_NAME.captures(line) {
                        let pkg = cap.get(1).unwrap().as_str().to_ascii_lowercase();
                        if let Some(intended) = lookup_squat(&pkg) {
                            findings.push(squat_finding(
                                &file.rel_path,
                                line_no,
                                cap.get(1).unwrap().start(),
                                cap.get(1).unwrap().end(),
                                &pkg,
                                intended,
                            ));
                        }
                    }
                }

                // import <pkg> in python
                if file.kind == FileKind::Python {
                    if let Some(cap) = PY_IMPORT.captures(line) {
                        let pkg = cap.get(1).unwrap().as_str().to_ascii_lowercase();
                        if let Some(intended) = lookup_squat(&pkg) {
                            findings.push(squat_finding(
                                &file.rel_path,
                                line_no,
                                cap.get(1).unwrap().start(),
                                cap.get(1).unwrap().end(),
                                &pkg,
                                intended,
                            ));
                        }
                    }
                }
            }
        }
        findings
    }
}

fn lookup_squat(name: &str) -> Option<&'static str> {
    TYPOSQUATS
        .iter()
        .find(|(s, _)| *s == name)
        .map(|(_, intended)| *intended)
}

fn squat_finding(
    file: &std::path::Path,
    line: usize,
    col_start: usize,
    col_end: usize,
    squat: &str,
    intended: &str,
) -> Finding {
    Finding {
        rule_id: META.id.into(),
        severity: META.severity,
        confidence: 95,
        file: file.to_path_buf(),
        span: Some(Span {
            line,
            col: col_start + 1,
            end_line: line,
            end_col: col_end + 1,
            byte_start: 0,
            byte_end: 0,
        }),
        message: format!("`{squat}` is a known typosquat — did you mean `{intended}`?"),
        remediation: META.default_remediation.into(),
        references: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::lookup_squat;

    #[test]
    fn detects_urllib_squat() {
        assert_eq!(lookup_squat("urllib"), Some("urllib3"));
    }

    #[test]
    fn ignores_canonical_name() {
        assert!(lookup_squat("urllib3").is_none());
        assert!(lookup_squat("requests").is_none());
    }
}
