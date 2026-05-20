use owo_colors::{OwoColorize, Stream};

use crate::model::{Finding, Report, Severity};

/// Print a `Report` to stdout in a human-readable format.
pub fn print(report: &Report, quiet: bool) {
    print_inner(report, quiet, false);
}

/// Print a `Report` with the per-rule profile appended.
pub fn print_with_profile(report: &Report) {
    print_inner(report, false, true);
}

fn print_inner(report: &Report, quiet: bool, profile: bool) {
    if !quiet {
        println!(
            "SkillScan v{}  •  rules: {}  •  target: {}",
            report.skillscan_version,
            report.stats.rules_run,
            report.target.display(),
        );
        println!();
    }

    if report.findings.is_empty() {
        if !quiet {
            println!(
                "{}  No findings.",
                "✓".if_supports_color(Stream::Stdout, owo_colors::OwoColorize::green)
            );
        }
    } else {
        for f in &report.findings {
            print_finding(f);
        }
    }

    if quiet {
        return;
    }

    println!();
    let summary = severity_summary(&report.findings);
    if summary.is_empty() {
        println!("Result: 0 findings");
    } else {
        println!("Result: {} findings ({summary})", report.findings.len());
    }
    println!(
        "Scanned {} files in {}ms.",
        report.stats.files_scanned, report.stats.duration_ms
    );

    if profile {
        println!();
        println!("Profile (per-rule wall time, top 10 slowest):");
        let mut timings: Vec<&crate::model::RuleTiming> = report.rule_timings.iter().collect();
        timings.sort_by_key(|t| std::cmp::Reverse(t.duration_us));
        for t in timings.iter().take(10) {
            let ms = t.duration_us as f64 / 1000.0;
            println!("  {:<16} {:>8.3} ms", t.rule_id, ms);
        }
    }
}

fn print_finding(f: &Finding) {
    let glyph = "✗"
        .if_supports_color(Stream::Stdout, owo_colors::OwoColorize::red)
        .to_string();
    let sev_str = format!("{:<8}", f.severity.as_str());
    let colored_sev = colorize_severity(f.severity, &sev_str);
    let loc = match &f.span {
        Some(s) => format!("{}:{}:{}", f.file.display(), s.line, s.col),
        None => f.file.display().to_string(),
    };
    println!(
        "{glyph} {colored_sev}  {:<14}  {}  ({loc})",
        f.rule_id, f.message
    );
}

fn colorize_severity(sev: Severity, s: &str) -> String {
    let stream = Stream::Stdout;
    match sev {
        Severity::Critical => s
            .if_supports_color(stream, |t| t.bright_red().bold().to_string())
            .to_string(),
        Severity::High => s
            .if_supports_color(stream, owo_colors::OwoColorize::red)
            .to_string(),
        Severity::Medium => s
            .if_supports_color(stream, owo_colors::OwoColorize::yellow)
            .to_string(),
        Severity::Low => s
            .if_supports_color(stream, owo_colors::OwoColorize::blue)
            .to_string(),
        Severity::Info => s
            .if_supports_color(stream, owo_colors::OwoColorize::cyan)
            .to_string(),
    }
}

fn severity_summary(findings: &[Finding]) -> String {
    let mut counts = [0usize; 5];
    for f in findings {
        let idx = match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        counts[idx] += 1;
    }
    let labels = ["critical", "high", "medium", "low", "info"];
    counts
        .iter()
        .zip(labels)
        .filter(|(c, _)| **c > 0)
        .map(|(c, l)| format!("{c} {l}"))
        .collect::<Vec<_>>()
        .join(", ")
}
