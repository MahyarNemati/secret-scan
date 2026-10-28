//! Findings and their redaction.

use serde::Serialize;

use crate::rules::{Confidence, Rule, Severity};

/// Where a finding came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// A file in the working tree.
    Worktree,
    /// A blob reachable from git history.
    History {
        commit: String,
        /// Short author identity, to route the fix to whoever introduced it.
        author: String,
        date: String,
    },
}

/// One detected secret.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: String,
    /// 1-indexed.
    pub line: usize,
    /// 1-indexed column of the secret within the line.
    pub column: usize,
    /// The line with the secret redacted. Never the raw secret: a scanner
    /// that prints credentials into CI logs has moved the leak, not fixed it.
    pub redacted: String,
    /// First and last few characters, enough to identify which credential it
    /// is without disclosing it.
    pub fingerprint: String,
    /// Shannon entropy of the secret, for triage.
    pub entropy: f64,
    pub remediation: String,
    pub origin: Origin,
}

impl Finding {
    /// Builds a finding, redacting as it goes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule: &Rule,
        path: String,
        line: usize,
        column: usize,
        line_text: &str,
        secret: &str,
        origin: Origin,
    ) -> Self {
        Finding {
            rule_id: rule.id.to_string(),
            description: rule.description.to_string(),
            severity: rule.severity,
            confidence: rule.confidence,
            path,
            line,
            column,
            redacted: redact_line(line_text, secret),
            fingerprint: fingerprint(secret),
            entropy: crate::entropy::shannon(secret),
            remediation: rule.remediation.to_string(),
            origin,
        }
    }

    /// A stable key for deduplication across the worktree and history scans.
    pub fn dedupe_key(&self) -> String {
        format!("{}:{}:{}", self.rule_id, self.path, self.fingerprint)
    }
}

/// Replaces the secret inside a line with a marker, and trims the result so a
/// minified bundle does not produce a 200 KB finding.
pub fn redact_line(line: &str, secret: &str) -> String {
    let replaced = if secret.is_empty() {
        line.to_string()
    } else {
        line.replace(secret, &format!("[REDACTED:{}]", secret.len()))
    };
    let trimmed = replaced.trim();
    const MAX: usize = 200;
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }
    let kept: String = trimmed.chars().take(MAX).collect();
    format!("{kept}… (line truncated)")
}

/// First four and last four characters, which is enough to match a finding
/// against a credential in a dashboard without revealing it.
pub fn fingerprint(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 10 {
        // Too short to show any of it safely.
        return format!("<{} chars>", chars.len());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}
