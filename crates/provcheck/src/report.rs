use serde::{Deserialize, Serialize};

/// The outcome of verifying a single file.
///
/// `verified` is the load-bearing field — everything else is
/// descriptive. Callers that only care about pass/fail should check
/// that one boolean; callers that display the manifest should walk
/// the richer fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// True iff the file carries a C2PA manifest that parses cleanly
    /// and whose signature validates. If `VerifyOptions::require_trusted`
    /// is set, also requires the signing certificate to be trusted.
    pub verified: bool,

    /// True iff the file has NO C2PA manifest at all (as distinct from
    /// a manifest that exists but fails verification).
    pub unsigned: bool,

    /// Tri-state trust-list membership:
    ///
    /// - `Some(true)`  — signing cert chains to a trusted root
    ///   (default C2PA list or user-provided anchors).
    /// - `Some(false)` — cert does NOT chain to any trusted root
    ///   (typical for per-install signers like rAIdio.bot's pattern).
    /// - `None` — no manifest, or trust status couldn't be determined
    ///   from the validation log.
    ///
    /// This field is reported regardless of `VerifyOptions::require_trusted`
    /// so policy decisions stay in the caller's hands.
    pub trusted: Option<bool>,

    /// Human-readable reason when `verified` is false. `None` when
    /// everything's fine.
    pub failure_reason: Option<String>,

    /// Identifier of the active manifest (`c2pa.id`), if any.
    pub active_manifest: Option<String>,

    /// Signer (certificate subject common name) of the active
    /// manifest, if any.
    pub signer: Option<String>,

    /// ISO-8601 timestamp of signing, if recorded.
    pub signed_at: Option<String>,

    /// Tool that produced the manifest (`claim_generator`).
    pub claim_generator: Option<String>,

    /// Free-form claim summary — assertion label → JSON value. Exposes
    /// AI-model assertions, training-data attestations, creator info,
    /// edit actions, etc.
    pub assertions: serde_json::Value,

    /// Count of ingredient manifests (parent files this one was
    /// derived from). 0 for a root artefact; >0 for edits / remixes.
    pub ingredient_count: usize,

    /// MIME type / format as reported by `c2pa`.
    pub format: Option<String>,

    /// Number of validation status entries. Zero means no validation
    /// errors; >0 means the signature or manifest had integrity issues
    /// (after filtering out codes that reflect trust-policy choices
    /// provcheck deliberately doesn't enforce by default).
    pub validation_errors: usize,
}

impl Report {
    /// Exit code convention used by the CLI.
    ///
    /// `0` — signed and verified (including trust, if required).
    /// `1` — unsigned OR invalid.
    /// The `2` exit-code for I/O errors is handled at the CLI layer,
    /// not by the report.
    pub fn exit_code(&self) -> i32 {
        if self.verified { 0 } else { 1 }
    }
    /// Helper for pretty-printed JSON (stable key order via `serde_json` default).
    pub fn to_json_string(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

use std::fmt::{Display, Formatter};
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
        if let Some(format) = &self.format {
            let _ = writeln!(f, "  format: {}", format);
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
