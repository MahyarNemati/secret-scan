//! End-to-end CLI behaviour: exit codes, formats, config and the git paths.

use std::fs;
use std::path::Path;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// Fake credentials, assembled at runtime so no matchable literal sits in the
/// source. GitHub's push protection scans this repository and rejects a push
/// containing them -- which is a fitting problem for a secret scanner to have.
fn gh_token() -> String {
    format!("{}{}", "ghp_", "16C7e42F292c6912E7710c838347Ae178B4a")
}

fn stripe_test_key() -> String {
    format!("{}{}", "sk_", "test_4eC39HqLyjWDarjtT1zdp7dc")
}

fn bin() -> Command {
    Command::cargo_bin("secret-scan").expect("binary builds")
}

fn write(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "t@example.test"]);
    git(dir, &["config", "user.name", "Test"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

// ---------------- exit codes ----------------

#[test]
fn clean_tree_exits_zero() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", "print('hello')\n");

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no secrets found"));
}

#[test]
fn finding_a_secret_exits_one() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("AWS access key ID"));
}

#[test]
fn no_fail_reports_without_failing() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));

    bin()
        .args(["--no-color", "--no-fail", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("AWS access key ID"));
}

#[test]
fn fail_on_threshold_is_respected() {
    let dir = TempDir::new().unwrap();
    // A Stripe *test* key is low severity.
    write(
        dir.path(),
        "app.py",
        &format!("K = \"{}\"\n", stripe_test_key()),
    );

    // Default threshold is medium, so a low finding must not fail.
    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .success();

    // Lowering the threshold to low must fail.
    bin()
        .args([
            "--no-color",
            "--fail-on",
            "low",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1);
}

#[test]
fn a_bad_config_is_an_error_not_a_finding() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", "x = 1\n");
    write(
        dir.path(),
        "bad.toml",
        "disabled_rules = [\"no-such-rule\"]\n",
    );

    bin()
        .args([
            "--no-color",
            "--config",
            dir.path().join("bad.toml").to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"));
}

// ---------------- output never contains secrets ----------------

#[test]
fn no_output_format_ever_prints_the_secret() {
    let dir = TempDir::new().unwrap();
    let gh = gh_token();
    write(dir.path(), "app.py", &format!("T = \"{gh}\"\n"));

    for format in ["text", "json", "sarif"] {
        let out = bin()
            .args([
                "--no-color",
                "--no-fail",
                "-f",
                format,
                dir.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains(&gh),
            "the {format} output leaked the secret:\n{stdout}"
        );
        assert!(
            stdout.contains("github") || stdout.contains("GitHub"),
            "the {format} output should still identify the rule:\n{stdout}"
        );
    }
}

// ---------------- formats ----------------

#[test]
fn json_output_is_parseable_and_summarised() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));

    let out = bin()
        .args(["--no-fail", "-f", "json", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");

    assert_eq!(doc["summary"]["total"], 1);
    assert_eq!(doc["summary"]["critical"], 1);
    assert_eq!(doc["findings"][0]["rule_id"], "aws-access-key-id");
    assert_eq!(doc["findings"][0]["severity"], "critical");
    assert_eq!(doc["findings"][0]["line"], 1);
}

#[test]
fn sarif_output_is_valid_and_self_consistent() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));

    let out = bin()
        .args(["--no-fail", "-f", "sarif", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");

    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "secret-scan");

    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());

    let declared: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    for r in results {
        let id = r["ruleId"].as_str().unwrap();
        assert!(
            declared.contains(&id),
            "result references rule {id} which is not declared"
        );
        // A zero startLine is invalid SARIF and GitHub rejects the upload.
        let line = r["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap();
        assert!(line >= 1, "startLine must be >= 1, got {line}");
        assert!(["error", "warning", "note"].contains(&r["level"].as_str().unwrap()));
    }
}

#[test]
fn writes_to_a_file_when_asked() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    let out_path = dir.path().join("out.sarif");

    bin()
        .args([
            "--no-fail",
            "-f",
            "sarif",
            "-o",
            out_path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let body = fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&body).expect("valid SARIF on disk");
}

// ---------------- configuration ----------------

#[test]
fn disabled_rule_is_not_reported() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    write(
        dir.path(),
        ".secret-scan.toml",
        "disabled_rules = [\"aws-access-key-id\"]\n",
    );

    bin()
        .args([
            "--no-color",
            "--config",
            dir.path().join(".secret-scan.toml").to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn allow_entry_suppresses_and_is_reportable() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "fixtures/sample.py",
        &format!("KEY = \"{AWS_KEY}\"\n"),
    );
    write(
        dir.path(),
        ".secret-scan.toml",
        r#"
[[allow]]
path = "fixtures/**"
reason = "test fixtures use AWS's own documented example key"
"#,
    );

    bin()
        .args([
            "--no-color",
            "--show-suppressed",
            "--config",
            dir.path().join(".secret-scan.toml").to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        // The reason must be visible: a silent suppression is
        // indistinguishable from a missed leak.
        .stdout(predicate::str::contains("test fixtures use AWS"));
}

#[test]
fn an_allow_without_a_reason_is_rejected() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", "x = 1\n");
    write(
        dir.path(),
        "bad.toml",
        "[[allow]]\npath = \"x\"\nreason = \"\"\n",
    );

    bin()
        .args([
            "--config",
            dir.path().join("bad.toml").to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("reason"));
}

#[test]
fn an_allow_matching_everything_is_rejected() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "app.py", "x = 1\n");
    write(dir.path(), "bad.toml", "[[allow]]\nreason = \"trust me\"\n");

    bin()
        .args([
            "--config",
            dir.path().join("bad.toml").to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("matches everything"));
}

// ---------------- gitignore and skipping ----------------

#[test]
fn respects_gitignore_by_default_and_can_override() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), ".gitignore", "ignored/\n");
    write(
        dir.path(),
        "ignored/leak.py",
        &format!("KEY = \"{AWS_KEY}\"\n"),
    );
    init_repo(dir.path());

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .success();

    // --no-gitignore must find it: a gitignored file is still on disk, and a
    // developer's .env is the single most common place a secret lives.
    bin()
        .args(["--no-color", "--no-gitignore", dir.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn scans_dotfiles_such_as_dotenv() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        ".env",
        &format!("AWS_ACCESS_KEY_ID={AWS_KEY}\n"),
    );

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(".env"));
}

#[test]
fn skips_binary_files() {
    let dir = TempDir::new().unwrap();
    let mut body = format!("KEY = \"{AWS_KEY}\"").into_bytes();
    body.push(0); // a NUL byte makes it binary, as git decides it
    fs::write(dir.path().join("blob.dat"), body).unwrap();

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

// ---------------- git history ----------------

#[test]
fn finds_a_secret_removed_from_the_worktree_but_still_in_history() {
    // The case that matters most: `git rm` plus a new commit looks clean, and
    // the credential is still in the repository for anyone who clones it.
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());

    write(dir.path(), "config.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-qm", "add config"]);

    write(
        dir.path(),
        "config.py",
        "KEY = os.environ[\"AWS_ACCESS_KEY_ID\"]\n",
    );
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-qm", "move key to env"]);

    // The worktree is clean.
    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .success();

    // History is not.
    bin()
        .args(["--no-color", "--history", dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("history"))
        .stdout(predicate::str::contains("AWS access key ID"));
}

#[test]
fn history_findings_name_the_commit_and_author() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());
    write(dir.path(), "a.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-qm", "oops"]);

    // Remove it from the worktree. Findings are deduplicated by
    // rule+path+fingerprint, so while the secret is still in the file the
    // single surviving finding is the worktree one -- which is correct, since
    // the remediation is identical. The history origin is what matters once
    // the file looks clean.
    write(
        dir.path(),
        "a.py",
        "KEY = os.environ[\"AWS_ACCESS_KEY_ID\"]\n",
    );
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-qm", "move to env"]);

    let out = bin()
        .args([
            "--no-fail",
            "-f",
            "json",
            "--history",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    let origins: Vec<&serde_json::Value> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| &f["origin"])
        .collect();
    let history = origins
        .iter()
        .find_map(|o| o.get("history"))
        .unwrap_or_else(|| panic!("expected a history origin; got {origins:?}"));

    assert!(
        history["commit"].as_str().is_some_and(|c| !c.is_empty()),
        "history finding must name the commit: {history:?}"
    );
    assert_eq!(
        history["author"].as_str(),
        Some("Test"),
        "history finding should name the author so the fix can be routed"
    );
    assert!(
        history["date"]
            .as_str()
            .is_some_and(|d| d.starts_with("20")),
        "history finding must carry a date: {history:?}"
    );
}

// ---------------- staged files and the hook ----------------

#[test]
fn staged_scan_only_looks_at_what_is_staged() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());

    // Unstaged leak: the hook must not block on it.
    write(dir.path(), "unstaged.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    bin()
        .args(["--no-color", "--staged", dir.path().to_str().unwrap()])
        .assert()
        .success();

    // Now stage it.
    git(dir.path(), &["add", "unstaged.py"]);
    bin()
        .args(["--no-color", "--staged", dir.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn staged_scan_with_nothing_staged_succeeds() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());
    bin()
        .args(["--no-color", "--staged", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn installs_and_uninstalls_the_hook() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());

    bin()
        .args(["--install-hook", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("installed pre-commit hook"));

    let hook = dir.path().join(".git/hooks/pre-commit");
    assert!(hook.exists(), "hook was not written");
    let body = fs::read_to_string(&hook).unwrap();
    assert!(body.contains("secret-scan --staged"));
    // A bypass has to be documented, or people invent their own.
    assert!(body.contains("--no-verify"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&hook).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "hook must be executable, got {mode:o}");
    }

    bin()
        .args(["--uninstall-hook", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(!hook.exists(), "hook was not removed");
}

#[test]
fn refuses_to_clobber_someone_elses_hook() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());
    let hook = dir.path().join(".git/hooks/pre-commit");
    fs::write(&hook, "#!/bin/sh\necho mine\n").unwrap();

    bin()
        .args(["--install-hook", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--force"));

    // The existing hook must be untouched.
    assert!(fs::read_to_string(&hook).unwrap().contains("echo mine"));

    // --force overwrites.
    bin()
        .args(["--install-hook", "--force", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(fs::read_to_string(&hook).unwrap().contains("secret-scan"));
}

#[test]
fn uninstall_leaves_a_foreign_hook_alone() {
    let dir = TempDir::new().unwrap();
    init_repo(dir.path());
    let hook = dir.path().join(".git/hooks/pre-commit");
    fs::write(&hook, "#!/bin/sh\necho mine\n").unwrap();

    bin()
        .args(["--uninstall-hook", dir.path().to_str().unwrap()])
        .assert()
        .code(2);
    assert!(hook.exists(), "a foreign hook must not be deleted");
}

#[test]
fn install_hook_outside_a_repository_is_an_error() {
    let dir = TempDir::new().unwrap();
    bin()
        .args(["--install-hook", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a git repository"));
}

// ---------------- misc ----------------

#[test]
fn lists_rules() {
    bin()
        .arg("--list-rules")
        .assert()
        .success()
        .stdout(predicate::str::contains("aws-access-key-id"))
        .stdout(predicate::str::contains("rules"));
}

#[test]
fn no_generic_excludes_low_confidence_rules() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "app.py",
        "api_key = \"zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a\"\n",
    );

    bin()
        .args(["--no-color", dir.path().to_str().unwrap()])
        .assert()
        .code(1);

    bin()
        .args(["--no-color", "--no-generic", dir.path().to_str().unwrap()])
        .assert()
        .success();
}
