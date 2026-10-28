//! Output formats: human, JSON and SARIF.

use std::collections::BTreeSet;
use std::io::Write;

use anyhow::Result;
use serde_json::json;
use termcolor::{Color, ColorSpec, WriteColor};

use crate::finding::Origin;
use crate::scanner::Report;

/// Writes a human-readable report.
pub fn text<W: WriteColor>(w: &mut W, report: &Report, show_suppressed: bool) -> Result<()> {
    if report.findings.is_empty() {
        let mut ok = ColorSpec::new();
        ok.set_fg(Some(Color::Green)).set_bold(true);
        w.set_color(&ok)?;
        write!(w, "✓ no secrets found")?;
        w.reset()?;
        writeln!(
            w,
            " in {} file(s){}",
            report.files_scanned,
            if report.files_skipped > 0 {
                format!(", {} skipped", report.files_skipped)
            } else {
                String::new()
            }
        )?;
        if show_suppressed && !report.suppressed.is_empty() {
            writeln!(
                w,
                "\n{} finding(s) suppressed by configuration:",
                report.suppressed.len()
            )?;
            for (f, reason) in &report.suppressed {
                writeln!(w, "  {} {}:{} — {}", f.rule_id, f.path, f.line, reason)?;
            }
        }
        return Ok(());
    }

    for f in &report.findings {
        let mut sev = ColorSpec::new();
        sev.set_fg(Some(match f.severity {
            crate::rules::Severity::Critical => Color::Magenta,
            crate::rules::Severity::High => Color::Red,
            crate::rules::Severity::Medium => Color::Yellow,
            crate::rules::Severity::Low => Color::Cyan,
        }))
        .set_bold(true);

        w.set_color(&sev)?;
        write!(w, "{:<9}", f.severity.as_str())?;
        w.reset()?;
        writeln!(w, "{}", f.description)?;

        let mut dim = ColorSpec::new();
        dim.set_dimmed(true);

        match &f.origin {
            Origin::Worktree => {
                w.set_color(&dim)?;
                write!(w, "         ")?;
                w.reset()?;
                writeln!(w, "{}:{}:{}", f.path, f.line, f.column)?;
            }
            Origin::History {
                commit,
                author,
                date,
            } => {
                w.set_color(&dim)?;
                write!(w, "         ")?;
                w.reset()?;
                writeln!(
                    w,
                    "{} (history: commit {} by {} on {})",
                    f.path,
                    commit,
                    author,
                    date.chars().take(10).collect::<String>()
                )?;
            }
        }

        w.set_color(&dim)?;
        writeln!(
            w,
            "         rule:   {} ({:?} confidence)",
            f.rule_id, f.confidence
        )?;
        writeln!(
            w,
            "         secret: {} entropy {:.2}",
            f.fingerprint, f.entropy
        )?;
        writeln!(w, "         line:   {}", f.redacted)?;
        w.reset()?;

        let mut fix = ColorSpec::new();
        fix.set_fg(Some(Color::Cyan));
        w.set_color(&fix)?;
        writeln!(w, "         fix:    {}", f.remediation)?;
        w.reset()?;
        writeln!(w)?;
    }

    let mut bold = ColorSpec::new();
    bold.set_bold(true);
    w.set_color(&bold)?;
    write!(w, "{} secret(s) found", report.findings.len())?;
    w.reset()?;
    writeln!(
        w,
        " in {} file(s){}",
        report.files_scanned,
        if report.files_skipped > 0 {
            format!(", {} skipped", report.files_skipped)
        } else {
            String::new()
        }
    )?;

    if !report.suppressed.is_empty() {
        writeln!(w, "{} suppressed by configuration", report.suppressed.len())?;
    }

    // The most important line in the output. People reach for `git commit
    // --amend` and believe the problem is gone.
    let mut warn = ColorSpec::new();
    warn.set_fg(Some(Color::Yellow));
    w.set_color(&warn)?;
    writeln!(
        w,
        "\nRotate every credential above. Removing it from the repository does not \
         un-leak it: assume anything that was pushed has been collected."
    )?;
    w.reset()?;
    Ok(())
}

/// Writes the machine-readable report.
pub fn json<W: Write>(w: &mut W, report: &Report) -> Result<()> {
    let doc = json!({
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "findings": report.findings,
        "suppressed": report.suppressed.iter().map(|(f, reason)| json!({
            "finding": f,
            "reason": reason,
        })).collect::<Vec<_>>(),
        "summary": {
            "total": report.findings.len(),
            "critical": count(report, crate::rules::Severity::Critical),
            "high": count(report, crate::rules::Severity::High),
            "medium": count(report, crate::rules::Severity::Medium),
            "low": count(report, crate::rules::Severity::Low),
        },
    });
    serde_json::to_writer_pretty(&mut *w, &doc)?;
    writeln!(w)?;
    Ok(())
}

fn count(report: &Report, sev: crate::rules::Severity) -> usize {
    report.findings.iter().filter(|f| f.severity == sev).count()
}

/// Writes SARIF 2.1.0 so GitHub code scanning shows the findings inline on
/// the pull request.
pub fn sarif<W: Write>(w: &mut W, report: &Report) -> Result<()> {
    let rule_ids: BTreeSet<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();

    let rules: Vec<_> = rule_ids
        .iter()
        .filter_map(|id| crate::rules::by_id(id))
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.id,
                "shortDescription": { "text": r.description },
                "fullDescription": { "text": format!("{}. {}", r.description, r.remediation) },
                "help": { "text": r.remediation },
                "defaultConfiguration": { "level": r.severity.sarif_level() },
                "properties": {
                    "tags": ["security", "secret"],
                    "problem.severity": r.severity.as_str(),
                    "security-severity": security_severity(r.severity),
                },
            })
        })
        .collect();

    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            // SARIF regions are 1-indexed and a zero line is invalid, so a
            // history finding (which has no useful line) is pinned to line 1
            // with the commit in the message instead.
            let line = if f.line == 0 { 1 } else { f.line };
            let mut message = format!("{} ({})", f.description, f.fingerprint);
            if let Origin::History { commit, author, .. } = &f.origin {
                message = format!(
                    "{} ({}) introduced in commit {} by {}",
                    f.description, f.fingerprint, commit, author
                );
            }
            json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": { "text": message },
                "partialFingerprints": { "secretScanFingerprint": f.dedupe_key() },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path },
                        "region": {
                            "startLine": line,
                            "startColumn": f.column.max(1),
                        },
                    },
                }],
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secret-scan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/MahyarNemati/secret-scan",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    });

    serde_json::to_writer_pretty(&mut *w, &doc)?;
    writeln!(w)?;
    Ok(())
}

/// GitHub maps this numeric score onto its own severity labels.
fn security_severity(sev: crate::rules::Severity) -> &'static str {
    match sev {
        crate::rules::Severity::Critical => "9.5",
        crate::rules::Severity::High => "8.0",
        crate::rules::Severity::Medium => "5.0",
        crate::rules::Severity::Low => "3.0",
    }
}
