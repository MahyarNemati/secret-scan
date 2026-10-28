//! secret-scan: finds leaked credentials in source trees and git history.
//!
//! The design is shaped by one observation: a secret scanner lives or dies by
//! its false-positive rate. A tool that flags `password = "changeme"` in a
//! test fixture gets removed from the pre-commit hook within a week, and then
//! it catches nothing at all. So:
//!
//! * Structured patterns (`AKIA…`, `ghp_…`) are reported with no further
//!   checks, because nothing else looks like them.
//! * Generic patterns (`api_key = "…"`) are gated on Shannon entropy and a
//!   placeholder list, because the pattern alone matches every example in
//!   every README.
//! * Suppression is first class: `.secret-scan.toml` allows a specific rule,
//!   path or fingerprint, and every entry requires a written reason.
//!
//! Secrets are never printed. Findings carry a fingerprint (first and last
//! four characters) and a redacted line, because a scanner that echoes
//! credentials into CI logs has moved the leak rather than fixed it.

pub mod config;
pub mod entropy;
pub mod finding;
pub mod hook;
pub mod report;
pub mod rules;
pub mod scanner;
