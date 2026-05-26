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
