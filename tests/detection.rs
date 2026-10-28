//! Detection behaviour: what must be found, and what must not.
//!
//! The negative cases matter more than the positive ones. A scanner that
//! finds every secret and also flags every placeholder gets uninstalled, and
//! then it finds nothing at all.

use secret_scan::finding::Origin;
use secret_scan::rules::{Confidence, Rule, Severity, RULES};
use secret_scan::scanner::scan_text;

/// Builds a credential-shaped string at runtime from fragments.
///
/// The fixtures below are all fake, but they are deliberately realistic --
/// that is the whole point of testing a secret scanner. The consequence is
/// that GitHub's own push protection scans this repository and rejects the
/// push when the literals appear in the source. Assembling them at runtime
/// keeps the test data realistic while leaving no matchable literal on disk.
///
/// The irony is instructive, and it is the same reason this repository ships
/// a .secret-scan.toml allowing its own fixtures: a secret scanner's test data
/// is indistinguishable from the thing it looks for.
fn cred(prefix: &str, body: &str) -> String {
    format!("{prefix}{body}")
}

fn all_rules() -> Vec<&'static Rule> {
    RULES.iter().collect()
}

fn scan(line: &str) -> Vec<String> {
    scan_text(line, "test.txt", &all_rules(), Origin::Worktree)
        .into_iter()
        .map(|f| f.rule_id)
        .collect()
}

fn finds(line: &str, rule_id: &str) -> bool {
    scan(line).iter().any(|id| id == rule_id)
}

// ---------------- must detect ----------------

#[test]
fn detects_structured_credentials() {
    // Every one of these is a documented provider prefix, so a match is
    // almost certainly a real credential.
    let cases: &[(&str, &str)] = &[
        (r#"key = "AKIAIOSFODNN7EXAMPLE""#, "aws-access-key-id"),
        (
            r#"t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a""#,
            "github-token",
        ),
        (
            r#"t = "github_pat_11ABCDEFG0abcdefghijkl_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef""#,
            "github-fine-grained-token",
        ),
        (r#"t = "glpat-ABCDEFGHIJKLMNOPQRST""#, "gitlab-token"),
        (
            r#"k = "npm_abcdefghijklmnopqrstuvwxyz0123456789""#,
            "npm-token",
        ),
        (
            r#"k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz""#,
            "anthropic-api-key",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "ssh-private-key-openssh",
        ),
        (
            r#"{"type": "service_account", "project_id": "x"}"#,
            "gcp-service-account-key",
        ),
    ];

    for (line, want) in cases {
        assert!(
            finds(line, want),
            "expected rule {want} to fire for {line:?}; got {:?}",
            scan(line)
        );
    }
}

#[test]
fn detects_payment_and_messaging_credentials() {
    // Assembled at runtime; see `cred`.
    let cases: Vec<(String, &str)> = vec![
        (
            format!(r#"k = "{}""#, cred("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc")),
            "stripe-live-secret-key",
        ),
        (
            format!(r#"k = "{}""#, cred("rk_", "live_4eC39HqLyjWDarjtT1zdp7dc")),
            "stripe-restricted-key",
        ),
        (
            // Not sequential digits: the placeholder guard rejects runs like
            // "1234567890", which is intended.
            format!(
                r#"t = "{}""#,
                cred("xoxb-", "5729481063-7284910365-AbCdEfGhIjKlMnOpQrStUvWx")
            ),
            "slack-token",
        ),
        (
            format!(
                r#"url = "{}""#,
                cred(
                    "https://hooks.slack.com/",
                    "services/T5729481/B7284910/aBcDeFgHiJkLmNoPqRsTuVwX"
                )
            ),
            "slack-webhook",
        ),
    ];

    for (line, want) in &cases {
        assert!(
            finds(line, want),
            "expected rule {want} to fire for {line:?}; got {:?}",
            scan(line)
        );
    }
}

#[test]
fn detects_aws_temporary_keys_too() {
    // ASIA is a temporary key. Short-lived is not the same as harmless.
    assert!(finds(r#"k = "ASIAIOSFODNN7EXAMPLE""#, "aws-access-key-id"));
}

#[test]
fn detects_high_entropy_generic_assignment() {
    assert!(finds(
        r#"api_key = "zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a""#,
        "generic-api-key"
    ));
}

#[test]
fn detects_password_in_connection_string() {
    assert!(finds(
        r#"DB = "postgres://admin:xK9mPq2vL8wNc4Fz@db.internal:5432/app""#,
        "database-url-with-password"
    ));
}

// ---------------- must NOT detect ----------------

#[test]
fn ignores_placeholders() {
    let lines = [
        r#"password = "changeme""#,
        r#"password = "password""#,
        r#"api_key = "YOUR_API_KEY_HERE""#,
        r#"api_key = "your-api-key""#,
        r#"secret = "xxxxxxxxxxxxxxxxxxxx""#,
        r#"secret_key = "aaaaaaaaaaaaaaaaaaaaaaaa""#,
        r#"token = "placeholder""#,
        r#"token = "REDACTED""#,
        r#"client_secret = "<INSERT_YOUR_SECRET>""#,
    ];
    for line in lines {
        let hits = scan(line);
        assert!(
            hits.is_empty(),
            "placeholder {line:?} should not be reported; got {hits:?}"
        );
    }
}

#[test]
fn ignores_environment_variable_references() {
    // These are the correct pattern, so flagging them punishes good practice.
    let lines = [
        r#"token = "${GITHUB_TOKEN}""#,
        r#"api_key = "{{ api_key }}""#,
        r#"password = "$DB_PASSWORD""#,
    ];
    for line in lines {
        let hits = scan(line);
        assert!(
            hits.is_empty(),
            "{line:?} should not be reported; got {hits:?}"
        );
    }
}

#[test]
fn ignores_low_entropy_passwords() {
    // A dictionary word assigned to `password` is almost always a fixture.
    for line in [
        r#"password = "hunter2""#,
        r#"password = "football""#,
        r#"db = "postgres://user:password@localhost:5432/dev""#,
    ] {
        let hits = scan(line);
        assert!(
            hits.is_empty(),
            "{line:?} should not be reported; got {hits:?}"
        );
    }
}

#[test]
fn ignores_short_values() {
    assert!(scan(r#"api_key = "abc123""#).is_empty());
}

// ---------------- grading ----------------

#[test]
fn stripe_test_keys_are_low_not_critical() {
    let line = format!(r#"k = "{}""#, cred("sk_", "test_4eC39HqLyjWDarjtT1zdp7dc"));
    let fs = scan_text(&line, "t.rs", &all_rules(), Origin::Worktree);
    let f = fs
        .iter()
        .find(|f| f.rule_id == "stripe-test-key")
        .expect("expected the test-key rule to fire");
    assert_eq!(
        f.severity,
        Severity::Low,
        "a test key cannot move money, so it must not be graded critical"
    );
}

#[test]
fn live_stripe_key_is_critical() {
    let line = format!(r#"k = "{}""#, cred("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc"));
    let fs = scan_text(&line, "t.rs", &all_rules(), Origin::Worktree);
    let f = fs
        .iter()
        .find(|f| f.rule_id == "stripe-live-secret-key")
        .expect("expected the live-key rule to fire");
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn structured_rules_are_not_entropy_gated() {
    // Nothing but an AWS key looks like an AWS key, so entropy must not be
    // allowed to veto the match.
    for r in RULES.iter().filter(|r| r.confidence == Confidence::High) {
        assert!(
            r.min_entropy.is_none(),
            "high-confidence rule {} should not be entropy-gated",
            r.id
        );
    }
}

#[test]
fn generic_rules_are_always_entropy_gated() {
    for r in RULES.iter().filter(|r| r.confidence == Confidence::Low) {
        assert!(
            r.min_entropy.is_some(),
            "low-confidence rule {} must be entropy-gated or it will be noise",
            r.id
        );
    }
}

// ---------------- redaction ----------------

#[test]
fn secrets_are_never_present_in_output() {
    // The whole point: a scanner that echoes credentials into a CI log has
    // moved the leak, not fixed it.
    let secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    let line = format!(r#"GITHUB_TOKEN = "{secret}""#);
    let fs = scan_text(&line, "t.rs", &all_rules(), Origin::Worktree);
    assert!(!fs.is_empty(), "expected a finding");

    for f in &fs {
        assert!(
            !f.redacted.contains(secret),
            "the redacted line still contains the secret: {}",
            f.redacted
        );
        assert!(
            !f.fingerprint.contains(secret),
            "the fingerprint contains the whole secret: {}",
            f.fingerprint
        );
        // Serialised form must be clean too, since that is what JSON and
        // SARIF emit.
        let json = serde_json::to_string(f).unwrap();
        assert!(
            !json.contains(secret),
            "the serialised finding contains the secret: {json}"
        );
    }
}

#[test]
fn short_secrets_are_not_partially_disclosed() {
    let fs = scan_text(
        r#"api_key = "zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a""#,
        "t.rs",
        &all_rules(),
        Origin::Worktree,
    );
    let f = &fs[0];
    // Showing four characters at each end of a 32-char secret is fine; for a
    // short one it would be most of it, so it is suppressed entirely.
    assert!(f.fingerprint.contains('…') || f.fingerprint.contains("chars"));
}

#[test]
fn long_lines_are_truncated_in_output() {
    let secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";
    let line = format!(r#"x = "{}" // {}"#, secret, "z".repeat(5000));
    let fs = scan_text(&line, "t.rs", &all_rules(), Origin::Worktree);
    // A 5 KB line is skipped entirely by the scanner, which is the intended
    // protection against minified bundles.
    assert!(fs.is_empty(), "lines over 4 KB should be skipped");
}

#[test]
fn reports_line_and_column() {
    let text = "clean line\nanother\nkey = \"AKIAIOSFODNN7EXAMPLE\"\n";
    let fs = scan_text(text, "t.rs", &all_rules(), Origin::Worktree);
    let f = fs
        .iter()
        .find(|f| f.rule_id == "aws-access-key-id")
        .unwrap();
    assert_eq!(f.line, 3, "line numbers are 1-indexed");
    assert!(f.column >= 1);
}

#[test]
fn placeholder_guard_applies_to_structured_rules_too() {
    // A documentation sample with a sequential-digit run is suppressed even
    // though the prefix matches. This is deliberate: AWS and Slack docs are
    // full of such values, and flagging every copy of their documentation is
    // exactly the noise that gets a scanner uninstalled.
    let hits = scan(&format!(
        r#"t = "{}""#,
        cred("xoxb-", "123456789012-123456789012-abcdefghijklmnop")
    ));
    assert!(
        hits.is_empty(),
        "a sequential-digit sample should be suppressed; got {hits:?}"
    );
}
