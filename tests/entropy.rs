use secret_scan::entropy::{is_placeholder, passes, shannon};

#[test]
fn shannon_is_zero_for_empty_and_uniform_input() {
    assert_eq!(shannon(""), 0.0);
    // One repeated character carries no information.
    assert_eq!(shannon("aaaaaaaa"), 0.0);
}

#[test]
fn shannon_is_one_bit_for_a_balanced_binary_string() {
    assert!((shannon("abab") - 1.0).abs() < 1e-9);
}

#[test]
fn generated_credentials_score_higher_than_words() {
    let generated = shannon("zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a");
    let word = shannon("changeme");
    assert!(
        generated > word,
        "a generated credential ({generated:.2}) should out-score a word ({word:.2})"
    );
    assert!(
        generated > 4.0,
        "expected > 4 bits/char, got {generated:.2}"
    );
}

#[test]
fn placeholders_are_recognised() {
    for s in [
        "changeme",
        "CHANGEME",
        "password",
        "YOUR_API_KEY_HERE",
        "your-api-key",
        "xxxxxxxxxxxx",
        "${SECRET}",
        "{{ secret }}",
        "<INSERT_KEY>",
        "aaaaaaaaaaaaaaaa",
        "notasecret",
    ] {
        assert!(
            is_placeholder(s),
            "{s:?} should be treated as a placeholder"
        );
    }
}

#[test]
fn real_credentials_are_not_placeholders() {
    for s in [
        "zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ] {
        assert!(
            !is_placeholder(s),
            "{s:?} should not be treated as a placeholder"
        );
    }
}

#[test]
fn passes_enforces_length_before_entropy() {
    // A short high-entropy string is still too short to be a credential.
    assert!(!passes("aB3$", Some(2.0), 16));
}

#[test]
fn passes_always_rejects_placeholders_regardless_of_entropy() {
    // "YOUR_API_KEY_HERE" has a reasonable character spread, so entropy
    // alone would let it through. The placeholder list is what stops it.
    assert!(!passes("YOUR_API_KEY_HERE", Some(1.0), 4));
}

#[test]
fn passes_accepts_structured_matches_with_no_entropy_floor() {
    assert!(passes("AKIAIOSFODNN7EXAMPLE", None, 20));
}
