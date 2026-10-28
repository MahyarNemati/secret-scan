use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use termcolor::{ColorChoice, StandardStream};

use secret_scan::config::Config;
use secret_scan::rules::{Severity, RULES};
use secret_scan::{hook, report, scanner};

/// Exit codes are distinct so this composes in a pipeline: a scan that could
/// not run is a different problem from a scan that found a secret.
const EXIT_OK: u8 = 0;
const EXIT_FOUND: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Parser)]
#[command(
    name = "secret-scan",
    version,
    about = "Find leaked credentials in a source tree and its git history",
    after_help = "EXIT CODES:\n  0  nothing found, or nothing at or above --fail-on\n  1  \
                  a secret was found at or above --fail-on\n  2  the scan could not run\n\n\
                  EXAMPLES:\n  secret-scan                      scan the working tree\n  \
                  secret-scan --history             also scan every commit\n  \
                  secret-scan --staged              scan staged files (what the hook runs)\n  \
                  secret-scan --install-hook        install the pre-commit hook\n  \
                  secret-scan -f sarif -o out.sarif scan and emit SARIF"
)]
struct Args {
    /// Directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: Format,

    /// Write to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Configuration file.
    #[arg(long, default_value = ".secret-scan.toml")]
    config: PathBuf,

    /// Exit 1 when a finding of this severity or worse is present.
    /// Overrides `fail_on` in the config file. Defaults to medium.
    #[arg(long)]
    fail_on: Option<Severity>,

    /// Never exit non-zero because of findings; report only.
    #[arg(long, conflicts_with = "fail_on")]
    no_fail: bool,

    /// Also scan every blob reachable from git history.
    #[arg(long)]
    history: bool,

    /// Limit the history scan to the most recent N commits.
    #[arg(long, default_value_t = 0, value_name = "N")]
    history_depth: usize,

    /// Scan only the staged files. Used by the pre-commit hook.
    #[arg(long)]
    staged: bool,

    /// Exclude the low-confidence generic rules.
    #[arg(long)]
    no_generic: bool,

    /// Scan files that .gitignore excludes.
    #[arg(long)]
    no_gitignore: bool,

    /// Skip files larger than this many bytes.
    #[arg(long, default_value_t = 2 * 1024 * 1024, value_name = "BYTES")]
    max_file_size: u64,

    /// Show which findings were suppressed by configuration.
    #[arg(long)]
    show_suppressed: bool,

    /// Install the git pre-commit hook and exit.
    #[arg(long)]
    install_hook: bool,

    /// Remove the pre-commit hook and exit.
    #[arg(long)]
    uninstall_hook: bool,

    /// Overwrite an existing pre-commit hook.
    #[arg(long)]
    force: bool,

    /// Print the built-in rules and exit.
    #[arg(long)]
    list_rules: bool,

    /// Disable colour.
    #[arg(long)]
    no_color: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("secret-scan: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<u8> {
    let args = Args::parse();

    if args.list_rules {
        list_rules();
        return Ok(EXIT_OK);
    }

    if args.install_hook {
        let root = hook::repo_root(&args.path)?;
        let path = hook::install(&root, args.force)?;
        println!("installed pre-commit hook at {}", path.display());
        println!("it runs: secret-scan --staged --fail-on medium");
        return Ok(EXIT_OK);
    }

    if args.uninstall_hook {
        let root = hook::repo_root(&args.path)?;
        if hook::uninstall(&root)? {
            println!("removed the pre-commit hook");
        } else {
            println!("no pre-commit hook to remove");
        }
        return Ok(EXIT_OK);
    }

    let cfg = Config::load(&args.config)?;

    let mut opts = scanner::Options {
        root: args.path.clone(),
        history: args.history,
        history_depth: args.history_depth,
        include_low_confidence: !args.no_generic,
        respect_gitignore: !args.no_gitignore,
        max_file_bytes: args.max_file_size,
        ..Default::default()
    };

    if args.staged {
        let root = hook::repo_root(&args.path)?;
        opts.root = root.clone();
        opts.only = hook::staged_files(&root)?;
        if opts.only.is_empty() {
            // Nothing staged is a successful no-op, not an error: committing
            // only deletions must not block.
            return Ok(EXIT_OK);
        }
    }

    let report_data = scanner::scan(&opts, &cfg)?;

    // Write the report.
    match args.output {
        Some(ref path) => {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("create {}", path.display()))?;
            write_report(
                &mut file,
                &report_data,
                args.format,
                args.show_suppressed,
                false,
            )?;
        }
        None => {
            let color = if args.no_color {
                ColorChoice::Never
            } else {
                ColorChoice::Auto
            };
            match args.format {
                Format::Text => {
                    let mut out = StandardStream::stdout(color);
                    report::text(&mut out, &report_data, args.show_suppressed)?;
                }
                _ => {
                    let mut out = io::stdout().lock();
                    write_report(
                        &mut out,
                        &report_data,
                        args.format,
                        args.show_suppressed,
                        false,
                    )?;
                }
            }
        }
    }

    // Gate.
    // Precedence: an explicit flag beats the config file, which beats the
    // default. The other order means a flag silently does nothing, which is
    // worse than no flag at all.
    let threshold = args.fail_on.or(cfg.fail_on).unwrap_or(Severity::Medium);
    if args.no_fail {
        return Ok(EXIT_OK);
    }
    let worst = report_data.findings.iter().map(|f| f.severity).max();
    match worst {
        Some(w) if w >= threshold => {
            eprintln!(
                "\nsecret-scan: found a {} finding (threshold {})",
                w.as_str(),
                threshold.as_str()
            );
            Ok(EXIT_FOUND)
        }
        _ => Ok(EXIT_OK),
    }
}

fn write_report<W: Write>(
    w: &mut W,
    data: &scanner::Report,
    format: Format,
    show_suppressed: bool,
    _color: bool,
) -> Result<()> {
    match format {
        Format::Json => report::json(w, data),
        Format::Sarif => report::sarif(w, data),
        Format::Text => {
            // Writing text to a file: no colour support needed.
            let mut buf = termcolor::NoColor::new(w);
            report::text(&mut buf, data, show_suppressed)
        }
    }
}

fn list_rules() {
    println!("{:<32} {:<9} {:<8} DESCRIPTION", "ID", "SEVERITY", "CONF");
    for r in RULES.iter() {
        println!(
            "{:<32} {:<9} {:<8} {}",
            r.id,
            r.severity.as_str(),
            format!("{:?}", r.confidence).to_lowercase(),
            r.description
        );
    }
    println!("\n{} rules. Disable one in .secret-scan.toml:", RULES.len());
    println!("\n  disabled_rules = [\"generic-password\"]");
}
