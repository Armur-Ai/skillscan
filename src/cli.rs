//! Command-line interface.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use crate::engine::Engine;
use crate::loaders::DirectoryLoader;
use crate::model::Severity;
use crate::reporters::{html, json, markdown, sarif, terminal};
use crate::rules;

/// Security scanner for Claude Skills.
#[derive(Parser, Debug)]
#[command(name = "skillscan", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Disable colored terminal output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Log level: error, warn, info, debug, trace.
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: String,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan a Claude Skill for vulnerabilities.
    Scan(ScanArgs),

    /// Inspect the loaded rule set.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Path to a skill directory containing `SKILL.md`.
    pub path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Term)]
    pub format: Format,

    /// Minimum severity that causes a non-zero exit code.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,

    /// Path to an extra rule pack (directory of YAML rules). Not yet wired up.
    #[arg(long)]
    pub rules: Option<PathBuf>,

    /// Suppress non-essential output.
    #[arg(long)]
    pub quiet: bool,

    /// Print per-rule wall-time profile after the scan (terminal format only).
    #[arg(long)]
    pub profile: bool,

    /// Enable the LLM-assisted detection pass. Requires `ANTHROPIC_API_KEY` to be set.
    #[arg(long)]
    pub llm: bool,

    /// Maximum USD cost (estimated) before the LLM pass aborts. Default is conservative.
    #[arg(long, default_value_t = 0.10)]
    pub llm_budget_usd: f64,

    /// Override the Claude model used by the LLM pass.
    #[arg(long)]
    pub llm_model: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// Print every loaded rule with its metadata.
    List,
    /// Export the rule catalog as Markdown or JSON (for docs/CI).
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Md)]
        format: ExportFormat,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum ExportFormat {
    Md,
    Json,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum Format {
    Term,
    Json,
    Sarif,
    Md,
    Html,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<FailOn> for Severity {
    fn from(f: FailOn) -> Self {
        match f {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
            FailOn::Info => Severity::Info,
        }
    }
}

impl Cli {
    /// Dispatch the parsed CLI to the right command. Returns the desired process exit code.
    ///
    /// # Errors
    /// Returns an error if a command fails before it can produce a report (e.g. the target path
    /// does not exist).
    pub fn run(self) -> anyhow::Result<ExitCode> {
        let Cli {
            command,
            no_color,
            log_level: _,
        } = self;
        if no_color {
            owo_colors::set_override(false);
        }
        match command {
            Command::Scan(args) => run_scan(args),
            Command::Rules { action } => match action {
                RulesAction::List => {
                    list_rules();
                    Ok(ExitCode::from(0))
                }
                RulesAction::Export { format } => {
                    export_rules(format);
                    Ok(ExitCode::from(0))
                }
            },
        }
    }
}

fn run_scan(args: ScanArgs) -> anyhow::Result<ExitCode> {
    let skill = DirectoryLoader::new(&args.path).load()?;

    let mut all_rules = rules::builtin_rules();
    if let Some(user_pack) = &args.rules {
        all_rules.extend(rules::yaml::load_rules_from_dir(user_pack)?);
    }
    let engine = Engine::new(all_rules);
    let mut report = engine.scan(&skill);

    if args.llm {
        let cfg =
            crate::engine::llm::LlmConfig::from_env(args.llm_model.clone(), args.llm_budget_usd)?;
        let llm_findings = crate::engine::llm::analyze(&skill, &cfg)?;
        report.findings.extend(llm_findings);
        report.findings.sort_by(|a, b| {
            let aline = a.span.as_ref().map_or(0, |s| s.line);
            let bline = b.span.as_ref().map_or(0, |s| s.line);
            a.file
                .cmp(&b.file)
                .then(aline.cmp(&bline))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }

    match args.format {
        Format::Term => {
            if args.profile {
                terminal::print_with_profile(&report);
            } else {
                terminal::print(&report, args.quiet);
            }
        }
        Format::Json => json::print(&report)?,
        Format::Sarif => sarif::print(&report, &engine)?,
        Format::Md => markdown::print(&report),
        Format::Html => html::print(&report),
    }

    let threshold: Severity = args.fail_on.into();
    let exit_code = if report.count_at_or_above(threshold) > 0 {
        2
    } else {
        0
    };
    Ok(ExitCode::from(exit_code))
}

fn list_rules() {
    let rules = rules::builtin_rules();
    let engine = Engine::new(rules);
    println!("Loaded {} rules.\n", engine.rule_count());
    println!("{:<16} {:<9} {:<14}  NAME", "ID", "SEVERITY", "CATEGORY");
    println!("{}", "-".repeat(80));
    for meta in engine.rule_metas() {
        println!(
            "{:<16} {:<9} {:<14}  {}",
            meta.id,
            meta.severity.as_str(),
            category_str(meta.category),
            meta.name,
        );
    }
}

fn export_rules(format: ExportFormat) {
    let rules = rules::builtin_rules();
    let engine = Engine::new(rules);
    let mut metas: Vec<_> = engine.rule_metas().collect();
    metas.sort_by_key(|m| (category_order(m.category), m.id));

    match format {
        ExportFormat::Md => emit_markdown_catalog(&metas, engine.rule_count()),
        ExportFormat::Json => emit_json_catalog(&metas, engine.rule_count()),
    }
}

fn emit_markdown_catalog(metas: &[&'static crate::engine::RuleMeta], total: usize) {
    println!("# Rule catalog\n");
    println!(
        "Generated by `skillscan rules export --format md`. **{total} rules** across 8 categories.\n"
    );
    println!(
        "> This page is a snapshot. Run the command above to regenerate after adding rules.\n"
    );

    use crate::engine::Category;
    const CATEGORIES: &[(Category, &str)] = &[
        (Category::Injection, "Injection"),
        (Category::Permissions, "Permissions"),
        (Category::Exfiltration, "Exfiltration"),
        (Category::SupplyChain, "Supply chain"),
        (Category::Obfuscation, "Obfuscation"),
        (Category::Secrets, "Secrets"),
        (Category::Compliance, "Compliance"),
        (Category::CodeQuality, "Code quality"),
    ];

    for (cat, label) in CATEGORIES {
        let in_cat: Vec<_> = metas.iter().filter(|m| m.category == *cat).collect();
        if in_cat.is_empty() {
            continue;
        }
        println!("## {label} ({})\n", in_cat.len());
        println!("| ID | Severity | Name | Remediation |");
        println!("|----|----------|------|-------------|");
        for m in in_cat {
            let r = m.default_remediation.replace('\n', " ").replace('|', "\\|");
            let r_short = if r.len() > 120 {
                format!("{}…", &r[..120])
            } else {
                r
            };
            println!(
                "| `{}` | {} | {} | {r_short} |",
                m.id,
                m.severity.as_str(),
                m.name
            );
        }
        println!();
    }
}

fn emit_json_catalog(metas: &[&'static crate::engine::RuleMeta], total: usize) {
    let arr: Vec<serde_json::Value> = metas
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id,
                "name": m.name,
                "severity": m.severity.as_str(),
                "category": category_str(m.category),
                "default_remediation": m.default_remediation,
            })
        })
        .collect();
    let out = serde_json::json!({
        "total": total,
        "rules": arr,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn category_order(c: crate::engine::Category) -> u8 {
    use crate::engine::Category;
    match c {
        Category::Injection => 0,
        Category::Permissions => 1,
        Category::Exfiltration => 2,
        Category::SupplyChain => 3,
        Category::Obfuscation => 4,
        Category::Secrets => 5,
        Category::Compliance => 6,
        Category::CodeQuality => 7,
    }
}

fn category_str(c: crate::engine::Category) -> &'static str {
    use crate::engine::Category;
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
