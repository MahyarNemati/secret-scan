//! Configuration file (`.secret-scan.toml`), for allow-listing.
//!
//! Allow-listing is not optional in a tool like this. A scanner you cannot
//! silence gets removed from the hook, so the design goal is that every
//! suppression is explicit, narrow and reviewable in a diff.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::rules::Severity;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Rule IDs to disable entirely.
    #[serde(default)]
    pub disabled_rules: Vec<String>,

    /// Path globs never scanned.
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Specific, reviewed exceptions.
    #[serde(default)]
    pub allow: Vec<Allow>,

    /// Fail the run at this severity or worse.
    #[serde(default)]
    pub fail_on: Option<Severity>,

    /// Extra entropy applied on top of each rule's own floor, to tune
    /// noisiness without editing rules.
    #[serde(default)]
    pub entropy_bonus: Option<f64>,
}

/// One reviewed exception. At least one field must be set, or it would
/// suppress everything.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// Match against a finding's fingerprint, which is the safe way to allow
    /// one specific value without writing the secret into the config.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Why this is acceptable. Required: an undocumented suppression is
    /// indistinguishable from someone silencing a real leak.
    pub reason: String,
}

impl Config {
    /// Loads a config, returning the default when the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        for (i, a) in self.allow.iter().enumerate() {
            if a.rule.is_none() && a.path.is_none() && a.fingerprint.is_none() {
                anyhow::bail!(
                    "allow[{i}] matches everything: set at least one of rule, path or fingerprint"
                );
            }
            if a.reason.trim().is_empty() {
                anyhow::bail!("allow[{i}] needs a non-empty reason");
            }
        }
        for id in &self.disabled_rules {
            if crate::rules::by_id(id).is_none() {
                anyhow::bail!(
                    "disabled_rules contains unknown rule {id:?}; run --list-rules to see the valid IDs"
                );
            }
        }
        Ok(())
    }

    /// Reports whether a finding is allowed, and why.
    pub fn allows(&self, rule_id: &str, path: &str, fingerprint: &str) -> Option<&str> {
        self.allow
            .iter()
            .find(|a| {
                a.rule.as_deref().map_or(true, |r| r == rule_id)
                    && a.path.as_deref().map_or(true, |p| glob_match(p, path))
                    && a.fingerprint.as_deref().map_or(true, |f| f == fingerprint)
            })
            .map(|a| a.reason.as_str())
    }

    pub fn rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.iter().any(|r| r == rule_id)
    }

    pub fn path_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| glob_match(p, path))
    }
}

/// A deliberately small glob: `*` matches within a path segment, `**` across
/// segments. Pulling in a full glob crate for this would be the only
/// dependency used once.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    glob_inner(pattern.as_bytes(), path.as_bytes())
}

fn glob_inner(pat: &[u8], text: &[u8]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    // "**" consumes any number of characters, separators included.
    if pat.starts_with(b"**") {
        let rest = &pat[2..];
        let rest = if rest.starts_with(b"/") {
            &rest[1..]
        } else {
            rest
        };
        if rest.is_empty() {
            return true;
        }
        for i in 0..=text.len() {
            if glob_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pat[0] == b'*' {
        let rest = &pat[1..];
        // A single star stops at a path separator.
        let limit = text.iter().position(|&c| c == b'/').unwrap_or(text.len());
        for i in 0..=limit {
            if glob_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pat[0] == b'?' {
        return !text.is_empty() && text[0] != b'/' && glob_inner(&pat[1..], &text[1..]);
    }
    if !text.is_empty() && pat[0] == text[0] {
        return glob_inner(&pat[1..], &text[1..]);
    }
    false
}
