//! Detection rules.
//!
//! Each rule is a regex plus metadata. Rules fall into two families:
//!
//! * **Structured** — the credential has a recognisable shape (`AKIA…`,
//!   `ghp_…`, `sk_live_…`). These are high confidence: a match is almost
//!   certainly a real credential, because nothing else looks like that.
//! * **Generic** — an assignment to a suspiciously named variable. These are
//!   low confidence on their own, so they are additionally gated on entropy
//!   (see [`crate::entropy`]). Without that gate, `password = "changeme"` in a
//!   test fixture produces a finding and the tool gets switched off.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// How much to trust a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The pattern is specific to one credential type.
    High,
    /// The pattern is suggestive; entropy decides.
    Medium,
    /// Generic assignment; entropy decides, and false positives are expected.
    Low,
}

/// Severity of a leak, used for SARIF levels and exit gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// SARIF uses three levels, so map onto them.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity {other:?} (want low, medium, high or critical)"
            )),
        }
    }
}

/// One detection rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Stable identifier, safe to put in an allow-list.
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub pattern: Regex,
    /// When set, the match is only reported if the captured group named
    /// "secret" (or group 1) clears this Shannon-entropy threshold in
    /// bits/char. Structured rules leave this at None.
    pub min_entropy: Option<f64>,
    /// Minimum length of the captured secret, to suppress trivial values.
    pub min_len: usize,
    /// Remediation advice.
    pub remediation: &'static str,
}

impl Rule {
    /// Extracts the secret from a match: the named group `secret` if the
    /// pattern defines one, otherwise the whole match.
    pub fn extract<'t>(&self, caps: &regex::Captures<'t>) -> &'t str {
        caps.name("secret")
            .or_else(|| caps.get(1))
            .map(|m| m.as_str())
            .unwrap_or_else(|| caps.get(0).map(|m| m.as_str()).unwrap_or(""))
    }
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("built-in rule regex must compile")
}

/// The built-in rule set.
pub static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // ---------------- cloud providers ----------------
        Rule {
            id: "aws-access-key-id",
            description: "AWS access key ID",
            severity: Severity::Critical,
            confidence: Confidence::High,
            // AKIA = long-lived user key, ASIA = temporary. Both matter.
            pattern: re(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
            min_entropy: None,
            min_len: 20,
            remediation: "Deactivate the key in IAM, then rotate. Deleting the commit is not enough -- assume it is compromised.",
        },
        Rule {
            id: "aws-secret-access-key",
            description: "AWS secret access key",
            severity: Severity::Critical,
            confidence: Confidence::Medium,
            pattern: re(
                r#"(?i)aws[_\-\.]?(?:secret|sec)[_\-\.]?(?:access)?[_\-\.]?key[^\S\r\n]*[:=][^\S\r\n]*['"]?(?P<secret>[A-Za-z0-9/+=]{40})['"]?"#,
            ),
            // 40 chars of base64 has high entropy; a placeholder usually does not.
            min_entropy: Some(3.5),
            min_len: 40,
            remediation: "Deactivate and rotate the key pair in IAM.",
        },
        Rule {
            id: "gcp-service-account-key",
            description: "Google Cloud service account private key",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#""type"\s*:\s*"service_account""#),
            min_entropy: None,
            min_len: 0,
            remediation: "Delete the key in IAM and generate a new one. Prefer workload identity over key files.",
        },
        Rule {
            id: "azure-storage-key",
            description: "Azure storage account key",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r"(?i)AccountKey\s*=\s*(?P<secret>[A-Za-z0-9+/=]{66,100})"),
            min_entropy: None,
            min_len: 66,
            remediation: "Rotate the storage account key in the Azure portal.",
        },

        // ---------------- source hosts ----------------
        Rule {
            id: "github-token",
            description: "GitHub personal access, OAuth, app or refresh token",
            severity: Severity::Critical,
            confidence: Confidence::High,
            // ghp/gho/ghu/ghs/ghr are GitHub's documented prefixes.
            pattern: re(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
            min_entropy: None,
            min_len: 40,
            remediation: "Revoke the token at github.com/settings/tokens. GitHub also auto-revokes tokens it finds in public pushes.",
        },
        Rule {
            id: "github-fine-grained-token",
            description: "GitHub fine-grained personal access token",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"),
            min_entropy: None,
            min_len: 30,
            remediation: "Revoke the token at github.com/settings/tokens.",
        },
        Rule {
            id: "gitlab-token",
            description: "GitLab personal or project access token",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
            min_entropy: None,
            min_len: 26,
            remediation: "Revoke the token in GitLab under Access Tokens.",
        },

        // ---------------- payments ----------------
        Rule {
            id: "stripe-live-secret-key",
            description: "Stripe live secret key",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r"\b(sk_live_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_len: 28,
            remediation: "Roll the key in the Stripe dashboard immediately -- it can move money.",
        },
        Rule {
            id: "stripe-restricted-key",
            description: "Stripe restricted key",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(rk_live_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_len: 28,
            remediation: "Roll the restricted key in the Stripe dashboard.",
        },
        Rule {
            id: "stripe-test-key",
            description: "Stripe test key",
            severity: Severity::Low,
            confidence: Confidence::High,
            // Reported, but low: test keys cannot move money. Still worth
            // knowing about, since it shows secrets are being committed.
            pattern: re(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_len: 28,
            remediation: "Harmless in itself, but move it to an environment variable: the habit is the problem.",
        },

        // ---------------- messaging and SaaS ----------------
        Rule {
            id: "slack-token",
            description: "Slack API token",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
            min_entropy: None,
            min_len: 20,
            remediation: "Revoke the token in the Slack app settings.",
        },
        Rule {
            id: "slack-webhook",
            description: "Slack incoming webhook URL",
            severity: Severity::Medium,
            confidence: Confidence::High,
            pattern: re(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
            min_entropy: None,
            min_len: 0,
            remediation: "Delete and recreate the webhook: anyone with the URL can post to the channel.",
        },
        Rule {
            id: "sendgrid-api-key",
            description: "SendGrid API key",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"),
            min_entropy: None,
            min_len: 44,
            remediation: "Delete the key in SendGrid -- it can send mail as your domain.",
        },
        Rule {
            id: "twilio-api-key",
            description: "Twilio API key or account SID",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b((?:SK|AC)[0-9a-fA-F]{32})\b"),
            min_entropy: None,
            min_len: 34,
            remediation: "Rotate the credential in the Twilio console; it can send messages at your expense.",
        },
        Rule {
            id: "openai-api-key",
            description: "OpenAI API key",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"),
            min_entropy: None,
            min_len: 24,
            remediation: "Revoke the key in the OpenAI dashboard; usage is billed to you.",
        },
        Rule {
            id: "anthropic-api-key",
            description: "Anthropic API key",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
            min_entropy: None,
            min_len: 28,
            remediation: "Revoke the key in the Anthropic console; usage is billed to you.",
        },
        Rule {
            id: "npm-token",
            description: "npm access token",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r"\b(npm_[A-Za-z0-9]{36})\b"),
            min_entropy: None,
            min_len: 40,
            remediation: "Revoke the token with `npm token revoke` -- it can publish packages as you.",
        },

        // ---------------- private keys ----------------
        Rule {
            id: "private-key",
            description: "Private key block",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY(?: BLOCK)?-----"),
            min_entropy: None,
            min_len: 0,
            remediation: "Treat the key as compromised: generate a new pair and replace it everywhere.",
        },
        Rule {
            id: "ssh-private-key-openssh",
            description: "OpenSSH private key",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
            min_entropy: None,
            min_len: 0,
            remediation: "Generate a new key pair and remove the old public key from every authorized_keys.",
        },

        // ---------------- connection strings ----------------
        Rule {
            id: "database-url-with-password",
            description: "Database connection string containing a password",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: re(
                r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:(?P<secret>[^\s:@/]{6,})@[^\s/]+",
            ),
            min_entropy: Some(2.0),
            min_len: 6,
            remediation: "Move the URL to an environment variable and rotate the database password.",
        },
        Rule {
            id: "jwt",
            description: "JSON Web Token",
            severity: Severity::Medium,
            confidence: Confidence::High,
            // Three base64url segments. Often a sample token, hence medium.
            pattern: re(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
            min_entropy: None,
            min_len: 40,
            remediation: "If it is a real token, rotate the signing key: a JWT cannot be revoked individually.",
        },

        // ---------------- generic, entropy-gated ----------------
        Rule {
            id: "generic-api-key",
            description: "Generic API key assignment",
            severity: Severity::Medium,
            confidence: Confidence::Low,
            pattern: re(
                r#"(?i)\b(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|secret[_\-]?key)\b[^\S\r\n]*[:=][^\S\r\n]*['"]?(?P<secret>[A-Za-z0-9_\-+/=\.]{16,})['"]?"#,
            ),
            min_entropy: Some(3.5),
            min_len: 16,
            remediation: "Move the value to an environment variable or a secret manager, and rotate it.",
        },
        Rule {
            id: "generic-password",
            description: "Hard-coded password assignment",
            severity: Severity::Medium,
            confidence: Confidence::Low,
            pattern: re(
                r#"(?i)\b(?:password|passwd|pwd)\b[^\S\r\n]*[:=][^\S\r\n]*['"](?P<secret>[^'"\s]{8,})['"]"#,
            ),
            // Deliberately high: real passwords in config are often words, but
            // so is every placeholder, and a tool that cries wolf is deleted.
            min_entropy: Some(3.2),
            min_len: 8,
            remediation: "Move the password to an environment variable or a secret manager, and rotate it.",
        },
        Rule {
            id: "high-entropy-base64",
            description: "High-entropy base64 blob assigned to a variable",
            severity: Severity::Low,
            confidence: Confidence::Low,
            pattern: re(
                r#"(?i)\b(?:secret|token|key|credential)s?\b[^\S\r\n]*[:=][^\S\r\n]*['"](?P<secret>[A-Za-z0-9+/]{32,}={0,2})['"]"#,
            ),
            min_entropy: Some(4.2),
            min_len: 32,
            remediation: "Confirm whether this is a credential; if so, rotate it and move it out of the repository.",
        },
    ]
});

/// Looks up a rule by ID.
pub fn by_id(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}
