# secret-scan

[![CI](https://github.com/MahyarNemati/secret-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/MahyarNemati/secret-scan/actions/workflows/ci.yml)

Finds leaked credentials in a source tree **and in git history**, works as a
pre-commit hook, and emits SARIF so findings land in GitHub's Security tab.

```bash
cargo install --git https://github.com/MahyarNemati/secret-scan

secret-scan                    # scan the working tree
secret-scan --history          # scan every commit as well
secret-scan --install-hook     # block commits that would leak
```

```
critical AWS access key ID
         config.py (history: commit 8f2a1c9b4e03 by Sam on 2026-03-14)
         rule:   aws-access-key-id (High confidence)
         secret: AKIA…MPLE (20 chars) entropy 3.68
         line:   AWS_ACCESS_KEY_ID = "[REDACTED:20]"
         fix:    Deactivate the key in IAM, then rotate. Deleting the commit is not enough.
```

## The two things that make a secret scanner usable

### 1. It must scan history, not just the working tree

This is the failure mode that matters. Someone commits a key, notices, deletes
it in the next commit, and the working tree is clean — but the credential is
still in the repository, and will be in every clone, forever. A scanner that
only looks at `HEAD` reports a clean repo that is actively leaking.

`--history` walks every commit on every branch and scans the **lines each
commit added**, then reports the commit, author and date so the fix can be
routed to whoever introduced it. Scanning added lines rather than full trees
matters: the naive version re-reports every secret for every commit in which
it existed, and the output grows quadratically.

### 2. It must not cry wolf

A scanner that flags `password = "changeme"` in a test fixture gets removed
from the pre-commit hook within a week, and then it catches nothing at all. So
rules come in two families, treated differently:

**Structured** patterns match a documented credential shape — `AKIA…`,
`ghp_…`, `sk_live_…`, `glpat-…`. A match is reported with no further checks,
because nothing else looks like that.

**Generic** patterns match an assignment to a suspicious name, like
`api_key = "…"`. On their own these match every example in every README, so
they are gated on two extra things:

- **Shannon entropy.** A generated credential is near-uniform over its
  alphabet; a placeholder is a word. `"changeme"` scores 2.75 bits/char,
  `"zH8kQ2mXp9LwR4tYn6BvC3sD7fG1jK5a"` scores 5.00. Each generic rule carries
  its own floor.
- **A placeholder list.** Entropy alone lets some through:
  `"YOUR_API_KEY_HERE"` has a perfectly reasonable character spread. So known
  placeholders, repeated characters, sequential digit runs and templating
  syntax (`${VAR}`, `{{ var }}`, `$VAR`, `<VAR>`) are rejected outright.

The tests encode this as an invariant: **every** low-confidence rule must have
an entropy floor, and **no** high-confidence rule may have one. Both are
asserted, so a new rule cannot be added on the wrong side by accident.

## Secrets are never printed

A scanner that echoes credentials into a CI log has moved the leak, not fixed
it. Findings carry:

- a **redacted line** — the secret replaced with `[REDACTED:40]`,
- a **fingerprint** — `ghp_…8B4a (40 chars)`, enough to identify which
  credential it is without disclosing it, and suppressed entirely for secrets
  short enough that four characters at each end would be most of it.

There is a test asserting the raw secret appears in **no** output format, text,
JSON and SARIF included, and CI re-checks it against the built binary.

## Rules

24 built-in rules. `secret-scan --list-rules` prints them.

| Area | Covers |
|---|---|
| Cloud | AWS access keys (including temporary `ASIA…`) and secret keys, GCP service-account JSON, Azure storage keys |
| Source hosts | GitHub classic and fine-grained tokens, GitLab PATs |
| Payments | Stripe live, restricted and test keys |
| SaaS | Slack tokens and webhooks, SendGrid, Twilio, OpenAI, Anthropic, npm |
| Keys | PEM private key blocks, OpenSSH private keys |
| Connection strings | Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL URLs containing a password |
| Tokens | JWTs |
| Generic | API keys, passwords, high-entropy base64 — all entropy-gated |

Severity is calibrated to blast radius, not pattern cleverness. A Stripe
**live** key is `critical` because it can move money; a Stripe **test** key is
`low`, because it cannot — but it is still reported, since committing it shows
the habit is there.

## Pre-commit hook

```bash
secret-scan --install-hook
```

The hook runs `secret-scan --staged --fail-on medium`, so it scans what is
about to be committed rather than the whole tree. Design details that matter:

- **It refuses to clobber an existing `pre-commit` hook** it did not write,
  and prints the one line to add to yours instead. `--force` overrides.
- **It honours `core.hooksPath`**, or it would write the hook somewhere git
  never looks and silently protect nothing.
- **It documents `--no-verify`** in its own text. People will bypass a hook;
  better that they know the supported way than invent one. The hook text also
  says that a *habit* of bypassing means you should add a config exception
  instead.
- **Nothing staged is a successful no-op**, so committing only deletions is
  never blocked.

Uninstall with `--uninstall-hook`, which also refuses to delete a hook it did
not write.

## Configuration

`.secret-scan.toml`:

```toml
fail_on = "medium"

disabled_rules = ["generic-password"]
exclude_paths = ["vendor/**", "testdata/**"]

[[allow]]
path = "tests/fixtures/**"
reason = "fixtures use AWS's own documented example key"

[[allow]]
rule = "jwt"
fingerprint = "eyJh…c2Fz (184 chars)"
reason = "sample token in the API docs, signed with a throwaway key"
```

Three deliberate constraints:

- **`reason` is required.** An undocumented suppression is indistinguishable
  from someone silencing a real leak. CI fails on an empty reason.
- **An entry with no `rule`, `path` or `fingerprint` is rejected**, because it
  would suppress everything.
- **An unknown rule ID in `disabled_rules` is an error**, not a no-op, so a
  typo cannot silently re-enable a rule you thought you had turned off.

Allow-listing by **fingerprint** is the safe way to permit one specific value:
it identifies the credential without writing it into the config.

`--show-suppressed` prints what was allowed and why, so a suppression cannot
hide quietly.

**Precedence is CLI > config > default.** A `--fail-on` flag overrides the
config file; the other order would make the flag silently do nothing, which is
worse than not having it.

## CI use

Exit codes are distinct, so a scan that *could not run* is a different problem
from a scan that *found something*:

| Code | Meaning |
|---|---|
| 0 | nothing at or above the threshold |
| 1 | a secret was found at or above the threshold |
| 2 | the scan could not run (bad config, not a repository) |

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0          # --history needs real history, not a shallow clone

- name: Scan for secrets
  run: |
    cargo install --git https://github.com/MahyarNemati/secret-scan
    secret-scan --history --no-fail -f sarif -o results.sarif .

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

`fetch-depth: 0` is the line people miss: the default shallow clone has one
commit, so `--history` finds nothing and the job passes for a repository that
is leaking.

## Performance

The walk is `.gitignore`-aware and parallel (the `ignore` crate from ripgrep,
plus rayon). Four things are skipped, each for a reason:

- **binary files** — detected by a NUL byte in the first 8 KB, the same
  heuristic git uses;
- **known binary extensions** — a cheap check before reading;
- **files over 2 MB** (`--max-file-size`) — a minified bundle is rarely worth
  the scan;
- **lines over 4 KB** — regex backtracking over a 200 KB minified line is
  where a scanner appears to hang.

`--no-gitignore` scans ignored files too, which is worth running occasionally:
a developer's `.env` is the single most common place a real credential lives,
and it is usually gitignored. Dotfiles are **always** scanned, for the same
reason.

## Flags

```
--history                 also scan git history
--history-depth N         limit history to the most recent N commits
--staged                  scan only staged files (what the hook runs)
-f, --format <fmt>        text, json or sarif
-o, --output <file>       write to a file
--fail-on <severity>      low | medium | high | critical (default medium)
--no-fail                 report only, never exit non-zero
--no-generic              exclude the low-confidence generic rules
--no-gitignore            scan files .gitignore excludes
--max-file-size <bytes>   skip larger files (default 2 MiB)
--show-suppressed         show what the config allowed, and why
--config <file>           default .secret-scan.toml
--install-hook / --uninstall-hook / --force
--list-rules
--no-color
```

## Development

```bash
make test       # 51 tests
make lint       # fmt + clippy, warnings denied
make selfscan   # scan this repository, history included
```

CI dogfoods the tool against its own repository and history, verifies the
documented behaviour (a planted key is caught, placeholders are not, the
secret never appears in any output format, the hook blocks a staged secret and
`--no-verify` still works), validates the SARIF, and runs `cargo audit`.

This repository is naturally full of credential-shaped strings, so its own
`.secret-scan.toml` allows the test fixtures and rule definitions — with
written reasons, which is the practice the tool is trying to encourage.

### A fitting problem

The first push of this repository was **rejected by GitHub's own push
protection**, which detected the Stripe and Slack fixtures. They are fake, but
a realistic fake is indistinguishable from the real thing — that is precisely
what makes them useful test data.

The fixtures are therefore assembled at runtime from fragments
(`cred("sk_", "live_…")`), so no matchable literal sits in the source. That is
the same approach gitleaks and trufflehog take, and the reason is worth
stating plainly: you cannot test a secret scanner without data that looks like
secrets, and anything that looks like a secret will be treated as one.

Writing the example key into a *comment* in `.secret-scan.toml` also made the
tool flag its own config, which is correct — the config is scanned like any
other file.

## Limitations

- **The generic rules will miss credentials with no recognisable shape.** A
  32-character random string assigned to `cfg.value` is indistinguishable from
  a hash or an ID without context the scanner does not have.
- **Entropy is a heuristic.** `"Passw0rd!Passw0rd!"` scores high enough to be
  reported; `"correct horse battery staple"` does not. Both decisions are
  wrong, and both are the price of a usable false-positive rate.
- **History scanning is slower than it looks** on large repositories: it runs
  `git show` per commit. Use `--history-depth` for a quick pass.
- **No remediation automation.** It will not rewrite history for you, and
  deliberately so — `git filter-repo` rewrites every commit hash and needs a
  human who understands the consequences for everyone who has cloned.
- **Rotation is still your job.** The tool says so in its own output, because
  the most common mistake after finding a leaked key is amending the commit and
  believing the problem is gone. It is not: assume anything pushed has been
  collected.

## License

MIT — see [LICENSE](LICENSE).
