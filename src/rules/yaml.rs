//! YAML-defined rules.
//!
//! A `YamlRule` is the deserialized form of a rule file. `RegexRule` is the runtime form: a
//! single Rust impl of [`Rule`] that backs every YAML rule whose match is a regex against file
//! content. The rule metadata is `Box::leak`ed into `&'static` at load time so the same
//! `RuleMeta` shape works for built-in Rust rules and YAML rules.

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;

use crate::engine::{Category, Rule, RuleMeta};
use crate::model::{Finding, Severity, Skill, Span};

#[derive(Debug, Deserialize)]
struct YamlMatch {
    regex: String,
}

#[derive(Debug, Deserialize)]
pub struct YamlRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub category: Category,
    #[serde(default = "default_confidence")]
    pub confidence: u8,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(rename = "match")]
    match_: YamlMatch,
    #[serde(default = "default_files")]
    pub files: Vec<String>,
}

fn default_confidence() -> u8 {
    80
}

fn default_files() -> Vec<String> {
    vec!["**/*".to_string()]
}

#[derive(Debug)]
pub struct RegexRule {
    meta: &'static RuleMeta,
    confidence: u8,
    pattern: Regex,
    glob_set: GlobSet,
    message_template: String,
    references: Vec<String>,
}

impl RegexRule {
    /// Compile a `YamlRule` into an executable rule.
    ///
    /// # Errors
    /// Returns an error if the regex or any glob pattern in `files` is invalid.
    pub fn from_yaml(yr: YamlRule) -> Result<Self> {
        let id: &'static str = Box::leak(yr.id.into_boxed_str());
        let name: &'static str = Box::leak(yr.name.into_boxed_str());
        let remediation: &'static str = Box::leak(yr.remediation.into_boxed_str());

        let meta: &'static RuleMeta = Box::leak(Box::new(RuleMeta {
            id,
            name,
            severity: yr.severity,
            category: yr.category,
            default_remediation: remediation,
        }));

        let pattern =
            Regex::new(&yr.match_.regex).with_context(|| format!("invalid regex in rule {id}"))?;

        let mut gsb = GlobSetBuilder::new();
        for pat in &yr.files {
            gsb.add(Glob::new(pat).with_context(|| format!("invalid glob `{pat}` in rule {id}"))?);
        }
        let glob_set = gsb
            .build()
            .with_context(|| format!("building glob set for rule {id}"))?;

        Ok(Self {
            meta,
            confidence: yr.confidence,
            pattern,
            glob_set,
            message_template: yr.message,
            references: yr.references,
        })
    }
}

impl Rule for RegexRule {
    fn meta(&self) -> &'static RuleMeta {
        self.meta
    }

    fn check(&self, skill: &Skill) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in &skill.files {
            if !self.glob_set.is_match(&file.rel_path) {
                continue;
            }
            let Some(content) = &file.content else {
                continue;
            };

            let mut line_no = 0usize;
            for line in content.lines() {
                line_no += 1;
                if let Some(m) = self.pattern.find(line) {
                    findings.push(Finding {
                        rule_id: self.meta.id.into(),
                        severity: self.meta.severity,
                        confidence: self.confidence,
                        file: file.rel_path.clone(),
                        span: Some(Span {
                            line: line_no,
                            col: m.start() + 1,
                            end_line: line_no,
                            end_col: m.end() + 1,
                            byte_start: 0,
                            byte_end: 0,
                        }),
                        message: format_message(&self.message_template, m.as_str(), line_no),
                        remediation: self.meta.default_remediation.into(),
                        references: self.references.clone(),
                    });
                }
            }
        }

        findings
    }
}

fn format_message(template: &str, match_text: &str, line: usize) -> String {
    template
        .replace("{match}", match_text)
        .replace("{line}", &line.to_string())
}

/// YAML source for the built-in rule pack. Each entry is included at compile time so the binary
/// is self-contained.
const BUILTIN_YAML_PACK: &[(&str, &str)] = &[
    (
        "SKILL-INJ-003",
        include_str!("packs/builtin/SKILL-INJ-003-ignore-previous.yml"),
    ),
    (
        "SKILL-INJ-004",
        include_str!("packs/builtin/SKILL-INJ-004-role-switch.yml"),
    ),
    (
        "SKILL-INJ-005",
        include_str!("packs/builtin/SKILL-INJ-005-base64-blob.yml"),
    ),
    (
        "SKILL-INJ-007",
        include_str!("packs/builtin/SKILL-INJ-007-hidden-html-comment.yml"),
    ),
    (
        "SKILL-EXF-005",
        include_str!("packs/builtin/SKILL-EXF-005-clipboard.yml"),
    ),
    (
        "SKILL-EXF-006",
        include_str!("packs/builtin/SKILL-EXF-006-webhook.yml"),
    ),
    (
        "SKILL-SUP-005",
        include_str!("packs/builtin/SKILL-SUP-005-runtime-git-clone.yml"),
    ),
    (
        "SKILL-OBF-001",
        include_str!("packs/builtin/SKILL-OBF-001-eval-exec.yml"),
    ),
    (
        "SKILL-SEC-005",
        include_str!("packs/builtin/SKILL-SEC-005-jwt.yml"),
    ),
    (
        "SKILL-INJ-008",
        include_str!("packs/builtin/SKILL-INJ-008-long-line.yml"),
    ),
    (
        "SKILL-EXF-003",
        include_str!("packs/builtin/SKILL-EXF-003-credential-dirs.yml"),
    ),
    (
        "SKILL-SUP-003",
        include_str!("packs/builtin/SKILL-SUP-003-fetch-and-exec.yml"),
    ),
    (
        "SKILL-OBF-003",
        include_str!("packs/builtin/SKILL-OBF-003-pickle-marshal.yml"),
    ),
    (
        "SKILL-EXF-001",
        include_str!("packs/builtin/SKILL-EXF-001-paste-services.yml"),
    ),
    (
        "SKILL-SEC-002",
        include_str!("packs/builtin/SKILL-SEC-002-google-api-key.yml"),
    ),
    (
        "SKILL-OBF-002",
        include_str!("packs/builtin/SKILL-OBF-002-hex-blob.yml"),
    ),
    (
        "SKILL-SEC-003",
        include_str!("packs/builtin/SKILL-SEC-003-slack-token.yml"),
    ),
    (
        "SKILL-SEC-004",
        include_str!("packs/builtin/SKILL-SEC-004-stripe-key.yml"),
    ),
    (
        "SKILL-EXF-002",
        include_str!("packs/builtin/SKILL-EXF-002-dns-subdomain.yml"),
    ),
    (
        "SKILL-OBF-004",
        include_str!("packs/builtin/SKILL-OBF-004-compile-dynamic.yml"),
    ),
];

/// Load every YAML rule from a directory the user passed via `--rules <PATH>`.
///
/// Walks one level deep, picks up `*.yml` and `*.yaml` files, parses and compiles each. Errors
/// surface the offending file path so authors can find their typo.
///
/// # Errors
/// Returns an error if the directory cannot be read, or if any rule file fails to parse or
/// compile.
pub fn load_rules_from_dir(path: &std::path::Path) -> Result<Vec<Box<dyn Rule>>> {
    use std::ffi::OsStr;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let read_dir = std::fs::read_dir(path)
        .with_context(|| format!("reading rule pack directory {}", path.display()))?;

    for entry in read_dir {
        let entry = entry.with_context(|| format!("walking {}", path.display()))?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(OsStr::to_str).unwrap_or("");
        if !matches!(ext, "yml" | "yaml") {
            continue;
        }
        let src =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let yr: YamlRule =
            serde_yml::from_str(&src).with_context(|| format!("parsing rule {}", p.display()))?;
        let rr =
            RegexRule::from_yaml(yr).with_context(|| format!("compiling rule {}", p.display()))?;
        rules.push(Box::new(rr));
    }

    Ok(rules)
}

/// Load every built-in YAML rule. Panics if any built-in rule fails to parse or compile — that is
/// a developer bug, not a user error, so it should fail loudly at first invocation.
#[must_use]
pub fn load_builtin_yaml_rules() -> Vec<Box<dyn Rule>> {
    BUILTIN_YAML_PACK
        .iter()
        .map(|(id, src)| {
            let yr: YamlRule = serde_yml::from_str(src)
                .unwrap_or_else(|e| panic!("built-in YAML rule {id} failed to parse: {e}"));
            let rr = RegexRule::from_yaml(yr)
                .unwrap_or_else(|e| panic!("built-in YAML rule {id} failed to compile: {e}"));
            Box::new(rr) as Box<dyn Rule>
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_yaml() {
        let src = r"
id: TEST-INJ-999
name: test rule
severity: high
category: injection
message: hit `{match}`
remediation: do better
match:
  regex: 'hello world'
files:
  - '**/*.md'
";
        let yr: YamlRule = serde_yml::from_str(src).expect("parses");
        let rr = RegexRule::from_yaml(yr).expect("compiles");
        assert_eq!(rr.meta().id, "TEST-INJ-999");
        assert_eq!(rr.meta().severity, Severity::High);
    }

    #[test]
    fn invalid_regex_errors() {
        let src = r"
id: TEST-INJ-998
name: bad regex
severity: high
category: injection
message: x
remediation: y
match:
  regex: '['
";
        let yr: YamlRule = serde_yml::from_str(src).expect("parses");
        assert!(RegexRule::from_yaml(yr).is_err());
    }

    #[test]
    fn builtin_pack_loads_without_panic() {
        let rules = load_builtin_yaml_rules();
        assert!(!rules.is_empty());
    }

    #[test]
    fn format_message_substitutes_placeholders() {
        let out = format_message("found `{match}` at line {line}", "AKIA12345", 42);
        assert_eq!(out, "found `AKIA12345` at line 42");
    }
}
