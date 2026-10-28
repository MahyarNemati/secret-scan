//! Pre-commit hook installation and the staged-files scan.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

const HOOK_MARKER: &str = "# installed by secret-scan";

const HOOK_BODY: &str = r#"#!/usr/bin/env bash
# installed by secret-scan
#
# Blocks a commit that would introduce a credential. To bypass deliberately:
#   git commit --no-verify
# If you need to bypass this regularly, add a reviewed entry to
# .secret-scan.toml instead -- a habit of --no-verify defeats the hook.
set -euo pipefail

if ! command -v secret-scan >/dev/null 2>&1; then
  echo "secret-scan: not on PATH; skipping (install it or remove this hook)" >&2
  exit 0
fi

exec secret-scan --staged --fail-on medium
"#;

/// Returns the repository root.
pub fn repo_root(start: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args([
            "-C",
            &start.to_string_lossy(),
            "rev-parse",
            "--show-toplevel",
        ])
        .output()
        .context("run git rev-parse")?;
    if !out.status.success() {
        anyhow::bail!("not a git repository: {}", start.display());
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

/// Installs the pre-commit hook. Refuses to clobber an existing hook that
/// this tool did not write.
pub fn install(root: &Path, force: bool) -> Result<PathBuf> {
    // Honour core.hooksPath, or the hook is written where git will not look.
    let hooks_dir = hooks_path(root)?;
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("create {}", hooks_dir.display()))?;

    let hook = hooks_dir.join("pre-commit");
    if hook.exists() {
        let existing = std::fs::read_to_string(&hook).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) && !force {
            anyhow::bail!(
                "{} already exists and was not written by secret-scan.\n\
                 Re-run with --force to overwrite, or add this line to the existing hook:\n\
                 \n    secret-scan --staged --fail-on medium\n",
                hook.display()
            );
        }
    }

    std::fs::write(&hook, HOOK_BODY).with_context(|| format!("write {}", hook.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook, perms)?;
    }

    Ok(hook)
}

/// Removes the hook, but only if this tool wrote it.
pub fn uninstall(root: &Path) -> Result<bool> {
    let hook = hooks_path(root)?.join("pre-commit");
    if !hook.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(&hook).unwrap_or_default();
    if !existing.contains(HOOK_MARKER) {
        anyhow::bail!(
            "{} was not written by secret-scan; leaving it alone",
            hook.display()
        );
    }
    std::fs::remove_file(&hook)?;
    Ok(true)
}

fn hooks_path(root: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args([
            "-C",
            &root.to_string_lossy(),
            "config",
            "--get",
            "core.hooksPath",
        ])
        .output()
        .context("run git config")?;
    let configured = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !configured.is_empty() {
        let p = PathBuf::from(&configured);
        return Ok(if p.is_absolute() { p } else { root.join(p) });
    }
    Ok(root.join(".git").join("hooks"))
}

/// Lists staged files that are added or modified.
pub fn staged_files(root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args([
            "-C",
            &root.to_string_lossy(),
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACM",
        ])
        .output()
        .context("run git diff --cached")?;
    if !out.status.success() {
        anyhow::bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| root.join(l))
        .collect())
}
