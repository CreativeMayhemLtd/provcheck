//! Rendering adapters for [`crate::Report`].
//!
//! `to_json_string` and `to_human_string` are the two formats the CLI
//! and GUI both consume. Keeping rendering here — not scattered across
//! front-ends — means "what the user sees" is reviewable in one place.

use crate::Report;

/// Pretty-printed JSON (stable key order via `serde_json` default).
pub fn to_json_string(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

/// Multi-line plain-text report suitable for a terminal.
///
/// Layout is deliberately terse: one claim per line, section headers
/// in brackets. Readable in 80 columns.
pub fn to_human_string(report: &Report) -> String {
    use std::fmt::Write;

    let mut s = String::new();

    let trust = if report.verified {
        "VERIFIED"
    } else if report.unsigned {
        "UNSIGNED"
    } else {
        "INVALID"
    };
    let _ = writeln!(s, "[{}]", trust);

    if let Some(reason) = &report.failure_reason {
        let _ = writeln!(s, "  reason: {}", reason);
    }
    if let Some(fmt) = &report.format {
        let _ = writeln!(s, "  format: {}", fmt);
    }
    if let Some(manifest) = &report.active_manifest {
        let _ = writeln!(s, "  manifest: {}", manifest);
    }
    if let Some(signer) = &report.signer {
        let _ = writeln!(s, "  signer: {}", signer);
    }
    match report.trusted {
        Some(true) => {
            let _ = writeln!(s, "  trust: signer is in the configured trust store");
        }
        Some(false) => {
            let _ = writeln!(s, "  trust: signer is NOT in the configured trust store");
        }
        None => {
            // No trust-store configured — stay quiet. The absence of
            // this line means "trust was not evaluated", which matches
            // the default CLI invocation.
        }
    }
    if let Some(when) = &report.signed_at {
        let _ = writeln!(s, "  signed: {}", when);
    }
    if let Some(tool) = &report.claim_generator {
        let _ = writeln!(s, "  tool: {}", tool);
    }
    if report.ingredient_count > 0 {
        let _ = writeln!(
            s,
            "  ingredients: {} (derived content)",
            report.ingredient_count
        );
    }
    if report.validation_errors > 0 {
        let _ = writeln!(s, "  validation errors: {}", report.validation_errors);
    }

    if !report.assertions.is_null() {
        let _ = writeln!(s, "[assertions]");
        match &report.assertions {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let v_short = v.to_string();
                    let v_short = if v_short.len() > 200 {
                        format!("{}…", &v_short[..200])
                    } else {
                        v_short
                    };
                    let _ = writeln!(s, "  {} = {}", k, v_short);
                }
            }
            other => {
                let _ = writeln!(s, "  {}", other);
            }
        }
    }

    s
}
