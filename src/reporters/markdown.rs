//! Markdown reporter — designed to render well as a GitHub PR comment.
//!
//! The output is GFM (GitHub Flavored Markdown): a summary header, a findings table for at-a-
//! glance triage, and a per-finding remediation section.

use std::fmt::Write;

use crate::model::{Finding, Report, Severity};

/// Print a `Report` as Markdown on stdout.
pub fn print(report: &Report) {
    println!("{}", render(report));
}

fn render(report: &Report) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "# SkillScan report");
    let _ = writeln!(out);
    let _ = writeln!(out, "**Target:** `{}`  ", report.target.display());
    let _ = writeln!(
        out,
        "**SkillScan:** v{}  •  **Rules:** {}  •  **Findings:** {}  •  **Duration:** {}ms  ",
        report.skillscan_version,
        report.stats.rules_run,
        report.findings.len(),
        report.stats.duration_ms,
    );
    let _ = writeln!(out, "**Ruleset hash:** `{}`", report.ruleset_hash);
    let _ = writeln!(out);

    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings.");
        return out;
    }

    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Severity | Rule | Message | Location |");
    let _ = writeln!(out, "|----------|------|---------|----------|");
    for f in &report.findings {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | `{}` |",
            severity_label(f.severity),
            f.rule_id,
            escape_pipe(&f.message),
            location(f),
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Remediation");
    let _ = writeln!(out);
    let mut seen = std::collections::BTreeSet::new();
    for f in &report.findings {
        if !seen.insert(f.rule_id.as_str()) {
            continue;
        }
        let _ = writeln!(out, "### `{}` — {}", f.rule_id, severity_label(f.severity));
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", f.remediation);
        let _ = writeln!(out);
    }

    out
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn location(f: &Finding) -> String {
    match &f.span {
        Some(s) => format!("{}:{}:{}", f.file.display(), s.line, s.col),
        None => f.file.display().to_string(),
    }
}

/// Pipe characters are table cell separators in GFM. Escape them in messages so the table parses.
fn escape_pipe(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::model::{Finding, Report, ScanStats};

    fn report_with(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: 1,
            skillscan_version: "0.1.0".into(),
            target: PathBuf::from("/tmp/x"),
            findings,
            stats: ScanStats {
                files_scanned: 1,
                rules_run: 1,
                duration_ms: 4,
            },
            ruleset_hash: "a".repeat(64),
        }
    }

    #[test]
    fn empty_report_renders_no_findings() {
        let s = render(&report_with(vec![]));
        assert!(s.contains("No findings."));
    }

    #[test]
    fn finding_appears_in_table_and_remediation() {
        let f = Finding {
            rule_id: "SKILL-XX-001".into(),
            severity: Severity::High,
            confidence: 80,
            file: PathBuf::from("SKILL.md"),
            span: None,
            message: "boom".into(),
            remediation: "fix it".into(),
            references: vec![],
        };
        let s = render(&report_with(vec![f]));
        assert!(s.contains("| high | `SKILL-XX-001` | boom | `SKILL.md` |"));
        assert!(s.contains("### `SKILL-XX-001` — high"));
        assert!(s.contains("fix it"));
    }

    #[test]
    fn pipe_in_message_is_escaped() {
        let f = Finding {
            rule_id: "X".into(),
            severity: Severity::Low,
            confidence: 80,
            file: PathBuf::from("a"),
            span: None,
            message: "left | right".into(),
            remediation: "n/a".into(),
            references: vec![],
        };
        let s = render(&report_with(vec![f]));
        assert!(s.contains("left \\| right"));
    }
}
