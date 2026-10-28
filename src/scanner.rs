//! Walking a tree (or git history) and matching rules against file contents.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::config::Config;
use crate::entropy;
use crate::finding::{Finding, Origin};
use crate::rules::{Rule, RULES};

/// Files larger than this are skipped. A 20 MB minified bundle or a test
/// fixture of random bytes costs real time and almost never holds a
/// credential worth finding this way.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Extensions that are binary or generated often enough to skip by default.
const SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "svg", "pdf", "zip", "gz", "bz2",
    "xz", "zst", "tar", "7z", "rar", "jar", "war", "class", "so", "dylib", "dll", "exe", "bin",
    "o", "a", "wasm", "woff", "woff2", "ttf", "eot", "otf", "mp3", "mp4", "mov", "avi", "mkv",
    "wav", "flac", "ogg", "webm", "psd", "ai", "sketch", "lock", "sum",
];

/// Scan options.
pub struct Options {
    pub root: PathBuf,
    /// Only these paths, when non-empty. Used by the pre-commit hook to scan
    /// just what is staged.
    pub only: Vec<PathBuf>,
    /// Also scan every blob reachable from git history.
    pub history: bool,
    /// Limit history to this many commits; 0 means all.
    pub history_depth: usize,
    /// Include low-confidence rules.
    pub include_low_confidence: bool,
    /// Follow .gitignore. Off means scan everything.
    pub respect_gitignore: bool,
    pub max_file_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            root: PathBuf::from("."),
            only: Vec::new(),
            history: false,
            history_depth: 0,
            include_low_confidence: true,
            respect_gitignore: true,
            max_file_bytes: MAX_FILE_BYTES,
        }
    }
}

/// Outcome of a scan.
pub struct Report {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// Allowed findings, with the reason, so a run can show what it chose to
    /// ignore rather than hiding it.
    pub suppressed: Vec<(Finding, String)>,
}

/// Scans according to opts.
pub fn scan(opts: &Options, cfg: &Config) -> Result<Report> {
    let active: Vec<&Rule> = RULES
        .iter()
        .filter(|r| !cfg.rule_disabled(r.id))
        .filter(|r| opts.include_low_confidence || r.confidence != crate::rules::Confidence::Low)
        .collect();

    let files = if opts.only.is_empty() {
        collect_files(opts, cfg)?
    } else {
        opts.only
            .iter()
            .filter(|p| p.is_file())
            .cloned()
            .collect::<Vec<_>>()
    };

    let skipped = AtomicUsize::new(0);
    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|path| {
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => return Vec::new(),
            };
            if meta.len() > opts.max_file_bytes {
                skipped.fetch_add(1, Ordering::Relaxed);
                return Vec::new();
            }
            let contents = match std::fs::read(path) {
                Ok(c) => c,
                Err(_) => return Vec::new(),
            };
            if is_binary(&contents) {
                skipped.fetch_add(1, Ordering::Relaxed);
                return Vec::new();
            }
            let text = String::from_utf8_lossy(&contents);
            let rel = relative(&opts.root, path);
            scan_text(&text, &rel, &active, Origin::Worktree)
        })
        .collect();

    if opts.history {
        findings.extend(scan_history(opts, &active)?);
    }

    // Deduplicate: the same secret usually appears in both the worktree and
    // history, and reporting it twice doubles the apparent problem.
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.dedupe_key()));

    // Partition into reported and suppressed.
    let mut reported = Vec::new();
    let mut suppressed = Vec::new();
    for f in findings {
        match cfg.allows(&f.rule_id, &f.path, &f.fingerprint) {
            Some(reason) => suppressed.push((f, reason.to_string())),
            None => reported.push(f),
        }
    }

    reported.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok(Report {
        findings: reported,
        files_scanned: files.len(),
        files_skipped: skipped.load(Ordering::Relaxed),
        suppressed,
    })
}

/// Matches every rule against text. Exported so tests can exercise detection
/// without touching the filesystem.
pub fn scan_text(text: &str, path: &str, rules: &[&Rule], origin: Origin) -> Vec<Finding> {
    let mut out = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        // A line this long is a minified bundle or a data blob; regex
        // backtracking over it is where a scanner appears to hang.
        if line.len() > 4096 {
            continue;
        }
        for rule in rules {
            for caps in rule.pattern.captures_iter(line) {
                let secret = rule.extract(&caps);
                if !entropy::passes(secret, rule.min_entropy, rule.min_len) {
                    continue;
                }
                let column = caps.get(0).map(|m| m.start() + 1).unwrap_or(1);
                out.push(Finding::new(
                    rule,
                    path.to_string(),
                    idx + 1,
                    column,
                    line,
                    secret,
                    origin.clone(),
                ));
            }
        }
    }
    out
}

fn collect_files(opts: &Options, cfg: &Config) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(&opts.root);
    builder
        .hidden(false) // .env is hidden and is exactly what we want to read
        .git_ignore(opts.respect_gitignore)
        .git_global(opts.respect_gitignore)
        .git_exclude(opts.respect_gitignore)
        .follow_links(false);
    // Never descend into .git: the object store is compressed, so scanning it
    // as text finds nothing and costs a lot.
    builder.filter_entry(|e| e.file_name() != ".git");

    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.into_path();
        if skip_by_extension(&path) {
            continue;
        }
        let rel = relative(&opts.root, &path);
        if cfg.path_excluded(&rel) {
            continue;
        }
        files.push(path);
    }
    Ok(files)
}

fn skip_by_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SKIP_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// A NUL byte in the first 8 KB is the same heuristic git uses.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

/// Scans blobs reachable from history.
///
/// This is the part that matters in practice: deleting a secret in a later
/// commit does not remove it from the repository, and a scanner that only
/// looks at the worktree reports a clean tree for a repo that is still
/// leaking.
fn scan_history(opts: &Options, rules: &[&Rule]) -> Result<Vec<Finding>> {
    let mut args: Vec<String> = vec![
        "-C".into(),
        opts.root.to_string_lossy().into_owned(),
        "log".into(),
        "--all".into(),
        "--no-merges".into(),
        "--pretty=format:%H%x00%an%x00%aI".into(),
    ];
    if opts.history_depth > 0 {
        args.push(format!("-n{}", opts.history_depth));
    }

    let out = Command::new("git")
        .args(&args)
        .output()
        .context("run git log (is git installed and is this a repository?)")?;
    if !out.status.success() {
        anyhow::bail!(
            "git log failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let commits: Vec<(String, String, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\0');
            Some((
                parts.next()?.to_string(),
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("").to_string(),
            ))
        })
        .collect();

    let findings: Vec<Finding> = commits
        .par_iter()
        .flat_map(|(commit, author, date)| {
            // Only the diff introduced by the commit, not the whole tree at
            // that commit: otherwise every commit re-reports every secret
            // that existed at the time, and the output is quadratic.
            let patch = Command::new("git")
                .args([
                    "-C",
                    &opts.root.to_string_lossy(),
                    "show",
                    "--no-color",
                    "--unified=0",
                    "--diff-filter=AM",
                    "--format=",
                    commit,
                ])
                .output();
            let patch = match patch {
                Ok(o) if o.status.success() => o.stdout,
                _ => return Vec::new(),
            };
            let text = String::from_utf8_lossy(&patch);

            let origin = Origin::History {
                commit: commit.chars().take(12).collect(),
                author: author.clone(),
                date: date.clone(),
            };
            scan_patch(&text, rules, &origin)
        })
        .collect();

    Ok(findings)
}

/// Extracts added lines from a unified diff and scans those, tracking which
/// file each belongs to.
fn scan_patch(patch: &str, rules: &[&Rule], origin: &Origin) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut current = String::from("<unknown>");

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            current = rest.to_string();
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            continue;
        }
        let Some(added) = line.strip_prefix('+') else {
            continue;
        };
        // Line numbers in history are not useful for jumping to code, so
        // report 0 rather than a number that means nothing.
        out.extend(scan_text(added, &current, rules, origin.clone()));
    }

    for f in &mut out {
        f.line = 0;
    }
    out
}
