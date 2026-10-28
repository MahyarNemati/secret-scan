//! Shannon entropy, used to separate real credentials from placeholders.
//!
//! The observation this rests on: a generated credential is close to uniform
//! over its alphabet, while a placeholder is a word. `"changeme"` and
//! `"xK9$mPq2vL8wNc4F"` are both eight-plus characters assigned to something
//! called `password`; only one of them is a secret.
//!
//! Entropy is a heuristic, not a decision procedure. `"aaaaaaaaaaaaaaaa"` is
//! long and low entropy (good, suppressed), but `"Passw0rd!Passw0rd!"` is
//! moderately high (bad, reported) -- so the thresholds are tuned per rule and
//! only ever applied to the *low confidence* rules. A structured match like
//! `AKIA…` is never entropy-gated, because nothing but an AWS key looks like
//! an AWS key.

/// Shannon entropy in bits per character.
///
/// Returns 0.0 for an empty string.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    // Byte-wise is correct here: credentials are ASCII, and counting bytes
    // avoids paying for UTF-8 decoding on every candidate.
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Known placeholder values, matched case-insensitively against the whole
/// secret. Entropy alone lets some of these through: "YOUR_API_KEY_HERE" has
/// a reasonable spread of characters.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "password",
    "passw0rd",
    "secret",
    "example",
    "test",
    "dummy",
    "placeholder",
    "redacted",
    "xxxxxxxx",
    "todo",
    "fixme",
    "none",
    "null",
    "undefined",
    "your_api_key",
    "your-api-key",
    "your_api_key_here",
    "yourapikeyhere",
    "insert_key_here",
    "my_secret",
    "mysecret",
    "notasecret",
    "s3cr3t",
    "hunter2",
];

/// Substrings that mark a value as a sample rather than a credential.
const PLACEHOLDER_SUBSTRINGS: &[&str] = &[
    "example.com",
    "xxxxxxxxxx",
    "0000000000",
    "1234567890",
    "aaaaaaaaaa",
    "your-",
    "your_",
    "placeholder",
    "redacted",
    "<insert",
    "dummy",
];

/// Reports whether a value is an obvious placeholder.
pub fn is_placeholder(secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();

    if PLACEHOLDERS.iter().any(|p| lower == *p) {
        return true;
    }
    if PLACEHOLDER_SUBSTRINGS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // A value that is one repeated character carries no information no matter
    // how long it is.
    if let Some(first) = lower.bytes().next() {
        if lower.bytes().all(|b| b == first) {
            return true;
        }
    }
    // Templating syntax: ${VAR}, {{ var }}, %s, $VAR, <VAR>.
    if lower.starts_with("${")
        || lower.starts_with("{{")
        || lower.starts_with('<')
        || lower.starts_with('%')
        || (lower.starts_with('$') && lower.len() < 64)
    {
        return true;
    }
    false
}

/// Reports whether a candidate secret should be reported, given a rule's
/// entropy floor.
pub fn passes(secret: &str, min_entropy: Option<f64>, min_len: usize) -> bool {
    if secret.len() < min_len {
        return false;
    }
    if is_placeholder(secret) {
        return false;
    }
    match min_entropy {
        None => true,
        Some(floor) => shannon(secret) >= floor,
    }
}
