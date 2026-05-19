//! SARIF 2.1.0 reporter.
//!
//! Emits a `sarif-schema-2.1.0.json`-shaped log so the report can be consumed by GitHub Code
//! Scanning, GitLab, and SARIF-aware editors (VS Code SARIF Viewer, JetBrains Qodana, etc).
//!
//! What we emit:
//!
//! - `runs[].tool.driver.rules[]` — one entry per loaded rule, with `helpUri` pointing at the
//!   rule's docs page and a numeric `security-severity` so GitHub Code Scanning maps severity
//!   correctly.
//! - `runs[].results[]` — one entry per finding, with a `physicalLocation` carrying line/column.
//! - `runs[].invocations[]` — captures the `rulesetHash` so two scans are reproducible.

use serde::Serialize;

use crate::engine::{Category, Engine, RuleMeta};
use crate::model::{Finding, Report, Severity};

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const HELP_URI_BASE: &str = "https://armur-ai.github.io/skillscan/rules/";

/// Print a `Report` as SARIF 2.1.0 JSON on stdout.
///
/// # Errors
/// Returns an error if serialization fails. In practice this should not happen.
pub fn print(report: &Report, engine: &Engine) -> anyhow::Result<()> {
    let log = build_log(report, engine);
    let s = serde_json::to_string_pretty(&log)?;
    println!("{s}");
    Ok(())
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run<'a>>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Run<'a> {
    tool: Tool<'a>,
    results: Vec<SarifResult<'a>>,
    invocations: Vec<Invocation<'a>>,
    column_kind: &'static str,
}

#[derive(Serialize, Debug)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Driver<'a> {
    name: &'static str,
    full_name: &'static str,
    version: &'a str,
    information_uri: &'static str,
    rules: Vec<RuleDef>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RuleDef {
    id: String,
    name: String,
    short_description: TextContent,
    full_description: TextContent,
    default_configuration: Configuration,
    help_uri: String,
    properties: RuleProperties,
}

#[derive(Serialize, Debug)]
struct TextContent {
    text: String,
}

#[derive(Serialize, Debug)]
struct Configuration {
    level: &'static str,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RuleProperties {
    tags: Vec<String>,
    #[serde(rename = "security-severity")]
    security_severity: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    level: &'static str,
    message: TextContent,
    locations: Vec<Location>,
    properties: ResultProperties,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResultProperties {
    #[serde(rename = "security-severity")]
    security_severity: String,
    confidence: u8,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Invocation<'a> {
    execution_successful: bool,
    properties: InvocationProperties<'a>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct InvocationProperties<'a> {
    ruleset_hash: &'a str,
    duration_ms: u128,
    files_scanned: usize,
    rules_run: usize,
}

fn build_log<'a>(report: &'a Report, engine: &'a Engine) -> SarifLog<'a> {
    let rules: Vec<RuleDef> = engine.rule_metas().map(rule_def).collect();
    let results: Vec<SarifResult<'a>> = report.findings.iter().map(result_from).collect();
    let invocation = Invocation {
        execution_successful: true,
        properties: InvocationProperties {
            ruleset_hash: &report.ruleset_hash,
            duration_ms: report.stats.duration_ms,
            files_scanned: report.stats.files_scanned,
            rules_run: report.stats.rules_run,
        },
    };
    let run = Run {
        tool: Tool {
            driver: Driver {
                name: "skillscan",
                full_name: "SkillScan — security scanner for Claude Skills",
                version: &report.skillscan_version,
                information_uri: "https://github.com/Armur-Ai/skillscan",
                rules,
            },
        },
        results,
        invocations: vec![invocation],
        column_kind: "unicodeCodePoints",
    };
    SarifLog {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![run],
    }
}

fn rule_def(meta: &'static RuleMeta) -> RuleDef {
    RuleDef {
        id: meta.id.to_string(),
        name: meta.name.to_string(),
        short_description: TextContent {
            text: meta.name.to_string(),
        },
        full_description: TextContent {
            text: meta.default_remediation.to_string(),
        },
        default_configuration: Configuration {
            level: severity_to_level(meta.severity),
        },
        help_uri: format!("{HELP_URI_BASE}{}", meta.id),
        properties: RuleProperties {
            tags: vec![category_tag(meta.category).to_string()],
            security_severity: severity_to_security_score(meta.severity).to_string(),
        },
    }
}

fn result_from(finding: &Finding) -> SarifResult<'_> {
    let region = finding.span.as_ref().map(|s| Region {
        start_line: s.line,
        start_column: s.col,
        end_line: s.end_line,
        end_column: s.end_col,
    });
    SarifResult {
        rule_id: &finding.rule_id,
        level: severity_to_level(finding.severity),
        message: TextContent {
            text: finding.message.clone(),
        },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: finding.file.display().to_string(),
                },
                region,
            },
        }],
        properties: ResultProperties {
            security_severity: severity_to_security_score(finding.severity).to_string(),
            confidence: finding.confidence,
        },
    }
}

fn severity_to_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub Code Scanning uses `security-severity` to bucket findings on the alerts page. Numbers
/// follow CVSS-like 0-10 conventions.
fn severity_to_security_score(s: Severity) -> f32 {
    match s {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
        Severity::Info => 0.5,
    }
}

fn category_tag(c: Category) -> &'static str {
    match c {
        Category::Injection => "injection",
        Category::Permissions => "permissions",
        Category::Exfiltration => "exfiltration",
        Category::SupplyChain => "supply-chain",
        Category::Obfuscation => "obfuscation",
        Category::Secrets => "secrets",
        Category::Compliance => "compliance",
        Category::CodeQuality => "code-quality",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_levels_map_correctly() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    #[test]
    fn security_scores_are_monotonic() {
        assert!(
            severity_to_security_score(Severity::Critical)
                > severity_to_security_score(Severity::High)
        );
        assert!(
            severity_to_security_score(Severity::High)
                > severity_to_security_score(Severity::Medium)
        );
        assert!(
            severity_to_security_score(Severity::Medium)
                > severity_to_security_score(Severity::Low)
        );
        assert!(
            severity_to_security_score(Severity::Low) > severity_to_security_score(Severity::Info)
        );
    }
}
