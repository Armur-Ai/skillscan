//! Command-line interface.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

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

    /// Path to an extra rule pack (directory of YAML rules).
    #[arg(long)]
    pub rules: Option<PathBuf>,

    /// Suppress non-essential output.
    #[arg(long)]
    pub quiet: bool,

    /// Print per-rule timing information after the scan.
    #[arg(long)]
    pub profile: bool,
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
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Cli {
    /// Dispatch the parsed CLI to the right command. Returns the desired process exit code.
    ///
    /// # Errors
    /// Returns an error if a command fails before it can produce a report.
    pub fn run(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Scan(args) => {
                // Phase 0 placeholder: loader/engine/reporter wiring lands in Phase 1.
                println!(
                    "skillscan v{} — target: {}",
                    crate::VERSION,
                    args.path.display()
                );
                println!("(no rules loaded yet — see IMPLEMENTATION_PLAN.md Phase 1)");
                Ok(ExitCode::from(0))
            }
            Command::Rules { action } => match action {
                RulesAction::List => {
                    println!("No rules loaded yet.");
                    Ok(ExitCode::from(0))
                }
            },
        }
    }
}
