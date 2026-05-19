use std::sync::LazyLock;

use regex::Regex;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill, Span};

const META: RuleMeta = RuleMeta {
    id: "SKILL-SEC-001",
    name: "Hardcoded secret in skill bundle",
    severity: Severity::Critical,
    category: Category::Secrets,
    default_remediation:
        "Remove the secret from the bundle, rotate it immediately, and load credentials from \
         environment variables or a secret store at runtime.",
};

static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("static regex compiles"));

static GITHUB_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bgh[posur]_[A-Za-z0-9_]{36,}\b").expect("static regex compiles")
});

static PRIVATE_KEY_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")
        .expect("static regex compiles")
});

struct Pattern {
    re: &'static LazyLock<Regex>,
    kind: &'static str,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        re: &AWS_ACCESS_KEY,
        kind: "AWS access key",
    },
    Pattern {
        re: &GITHUB_TOKEN,
        kind: "GitHub token",
    },
    Pattern {
        re: &PRIVATE_KEY_HEADER,
        kind: "private key",
    },
];

#[derive(Debug)]
pub struct SecretsRule;

impl Rule for SecretsRule {
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
                for pat in PATTERNS {
                    if let Some(m) = pat.re.find(line) {
                        findings.push(Finding {
                            rule_id: META.id.into(),
                            severity: META.severity,
                            confidence: 95,
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
                                "Possible {} at line {line_no}, col {}",
                                pat.kind,
                                m.start() + 1
                            ),
                            remediation: META.default_remediation.into(),
                            references: vec![],
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::{AWS_ACCESS_KEY, GITHUB_TOKEN, PRIVATE_KEY_HEADER};

    #[test]
    fn detects_example_aws_key() {
        // Documented AWS example key — safe to use in test fixtures.
        assert!(AWS_ACCESS_KEY.is_match("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_pat_prefix() {
        let token = format!("ghp_{}", "a".repeat(36));
        assert!(GITHUB_TOKEN.is_match(&token));
    }

    #[test]
    fn detects_private_key_header() {
        assert!(PRIVATE_KEY_HEADER.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(PRIVATE_KEY_HEADER.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }
}
