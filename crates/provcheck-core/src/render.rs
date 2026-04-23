//! Rendering adapters for [`crate::Report`].
//!
//! `to_json_string` and `to_human_string` are the two formats the CLI
//! and GUI both consume. Keeping rendering here — not scattered across
//! front-ends — means "what the user sees" is reviewable in one place.

use std::fmt::{Display, Formatter};
use crate::Report;

/// Multi-line plain-text report suitable for a terminal.
impl Display for Report {

    /// Layout is deliberately terse: one claim per line, section headers
    /// in brackets. Readable in 80 columns.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let trust = if self.verified {
            "VERIFIED"
        } else if self.unsigned {
            "UNSIGNED"
        } else {
            "INVALID"
        };
        let _ = writeln!(f, "[{}]", trust);

        if let Some(reason) = &self.failure_reason {
            let _ = writeln!(f, "  reason: {}", reason);
        }
        if let Some(fmt) = &self.format {
            let _ = writeln!(f, "  format: {}", fmt);
        }
        if let Some(manifest) = &self.active_manifest {
            let _ = writeln!(f, "  manifest: {}", manifest);
        }
        if let Some(signer) = &self.signer {
            let _ = writeln!(f, "  signer: {}", signer);
        }
        match self.trusted {
            Some(true) => {
                let _ = writeln!(f, "  trust: signer is in the configured trust store");
            }
            Some(false) => {
                let _ = writeln!(f, "  trust: signer is NOT in the configured trust store");
            }
            None => {
                // No trust-store configured — stay quiet. The absence of
                // this line means "trust was not evaluated", which matches
                // the default CLI invocation.
            }
        }
        if let Some(when) = &self.signed_at {
            let _ = writeln!(f, "  signed: {}", when);
        }
        if let Some(tool) = &self.claim_generator {
            let _ = writeln!(f, "  tool: {}", tool);
        }
        if self.ingredient_count > 0 {
            let _ = writeln!(
                f,
                "  ingredients: {} (derived content)",
                self.ingredient_count
            );
        }
        if self.validation_errors > 0 {
            let _ = writeln!(f, "  validation errors: {}", self.validation_errors);
        }

        if !self.assertions.is_null() {
            let _ = writeln!(f, "[assertions]");
            let assertion_string = process_assertions(&self.assertions);
            let _ = writeln!(f, "{}", assertion_string);
        }

        Ok(())
    }
}

// Rendering specific helpers
impl Report {
    /// Helper for pretty-printed JSON (stable key order via `serde_json` default).
    pub fn to_json_string(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

fn process_assertions(assertions: &serde_json::Value) -> String {
    use std::fmt::Write;

    let mut s = String::new();

    match assertions {
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
    s
}