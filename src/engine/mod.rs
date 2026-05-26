//! Rule execution engine.

pub mod ast;
pub mod llm;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Finding, Report, ScanStats, Severity, Skill};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Injection,
    Permissions,
    Exfiltration,
    SupplyChain,
    Obfuscation,
    Secrets,
    Compliance,
    CodeQuality,
}

/// Static metadata for a rule. Held by-value as a `&'static` so rule registration is zero-alloc.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub default_remediation: &'static str,
}

/// A pluggable check against a loaded skill.
pub trait Rule: Send + Sync + std::fmt::Debug {
    fn meta(&self) -> &'static RuleMeta;
    fn check(&self, skill: &Skill) -> Vec<Finding>;
}

/// Runs a fixed set of rules against a `Skill` and produces a `Report`.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<Box<dyn Rule>>,
    ruleset_hash: String,
}

impl Engine {
    /// Construct an engine. Rules are sorted by id for deterministic execution and a SHA-256
    /// `ruleset_hash` is computed so two scans with the same rule set are comparable.
    #[must_use]
    pub fn new(mut rules: Vec<Box<dyn Rule>>) -> Self {
        rules.sort_by_key(|r| r.meta().id);
        let mut hasher = Sha256::new();
        for rule in &rules {
            hasher.update(rule.meta().id.as_bytes());
            hasher.update(b"\n");
        }
        let ruleset_hash = hex::encode(hasher.finalize());
        Self {
            rules,
            ruleset_hash,
        }
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Iterate metadata for every loaded rule (in deterministic id order).
    pub fn rule_metas(&self) -> impl Iterator<Item = &'static RuleMeta> + '_ {
        self.rules.iter().map(|r| r.meta())
    }

    /// SHA-256 of the loaded rule set, lowercase hex.
    #[must_use]
    pub fn ruleset_hash(&self) -> &str {
        &self.ruleset_hash
    }

    /// Run every rule against `skill` and collect findings.
    ///
    /// A rule that panics produces a `SKILL-ENG-001` finding rather than crashing the scan.
    #[must_use]
    pub fn scan(&self, skill: &Skill) -> Report {
        use rayon::prelude::*;

        let start = Instant::now();
        let per_rule: Vec<(&'static str, std::time::Duration, Vec<Finding>)> = self
            .rules
            .par_iter()
            .map(|rule| {
                let rule_id = rule.meta().id;
                let rule_start = Instant::now();
                let f = match catch_unwind(AssertUnwindSafe(|| rule.check(skill))) {
                    Ok(rule_findings) => rule_findings,
                    Err(_) => vec![panic_finding(rule_id)],
                };
                (rule_id, rule_start.elapsed(), f)
            })
            .collect();

        let mut findings: Vec<Finding> = Vec::new();
        let mut rule_timings: Vec<crate::model::RuleTiming> = Vec::with_capacity(per_rule.len());
        for (id, dur, f) in per_rule {
            rule_timings.push(crate::model::RuleTiming {
                rule_id: id.to_string(),
                duration_us: u64::try_from(dur.as_micros()).unwrap_or(u64::MAX),
            });
            findings.extend(f);
        }
        rule_timings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

        findings.sort_by(|a, b| {
            let aline = a.span.as_ref().map_or(0, |s| s.line);
            let bline = b.span.as_ref().map_or(0, |s| s.line);
            a.file
                .cmp(&b.file)
                .then(aline.cmp(&bline))
                .then(a.rule_id.cmp(&b.rule_id))
        });

        let duration = start.elapsed();
        Report {
            schema_version: 1,
            skillscan_version: crate::VERSION.into(),
            target: skill.root.clone(),
            findings,
            stats: ScanStats::new(skill.files.len(), self.rules.len(), duration),
            ruleset_hash: self.ruleset_hash.clone(),
            rule_timings,
        }
    }
}

fn panic_finding(rule_id: &'static str) -> Finding {
    Finding {
        rule_id: "SKILL-ENG-001".into(),
        severity: Severity::Medium,
        confidence: 100,
        file: PathBuf::new(),
        span: None,
        message: format!("Rule {rule_id} panicked during scan"),
        remediation: "Open an issue: https://github.com/Armur-Ai/skillscan/issues".into(),
        references: vec![],
    }
}
