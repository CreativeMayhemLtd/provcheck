use serde::{Deserialize, Serialize};

pub use provcheck_attestation_spec::IdentityClaim;

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

    /// DID-anchored attestation result. Always `None` from the offline
    /// `verify_with_options` path — populated only by
    /// `provcheck_platform::verify_with_attestation` when the caller
    /// asked for second-factor identity verification via
    /// `--bsky-handle` or `--did`. Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub did_attestation: Option<DidAttestation>,

    /// Self-asserted identity claim from the signed asset's
    /// `app.provcheck.identity` C2PA assertion, if present. Always
    /// reported when the assertion was found in the manifest — but
    /// the verifier MUST NOT trust this claim on its own. The
    /// surrounding flow (`--auto-identity` on the CLI, the GUI
    /// auto-fill) uses it as a hint to skip manual identity entry;
    /// the actual trust decision happens in the
    /// [`did_attestation`](Self::did_attestation) cross-check against
    /// the DID's `app.provcheck.signingKey` records. Omitted from
    /// JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<IdentityClaim>,

    /// Neural-watermark detection results. Always empty from
    /// the core `verify_with_options` path — populated only by
    /// callers that invoked one or more detectors (the
    /// silentcipher detector lives in `provcheck-watermark`;
    /// future sibling crates will add AudioSeal, WavMark, and
    /// any other FOSS-licensed families) and pushed each
    /// result into this vec.
    ///
    /// Independent of C2PA: these signals corroborate or
    /// contradict the manifest rather than relying on the same
    /// trust chain. Each entry's [`WatermarkResult::kind`]
    /// identifies which detector ran. Multiple entries are
    /// expected once a build ships more than one detector; the
    /// order is detector-driven (registration order).
    ///
    /// Omitted from JSON when empty so a `--no-watermark` run
    /// or a build with no detectors compiled in produces
    /// indistinguishable output.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub watermarks: Vec<WatermarkResult>,
}

/// Outcome of a DID-anchored second-factor check, populated on
/// [`Report::did_attestation`] when the caller routed through
/// `provcheck_platform::verify_with_attestation`. Renderers should
/// treat the `status` field as load-bearing and the rest as
/// descriptive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidAttestation {
    /// The DID the check was performed against (resolved from handle
    /// if the caller supplied a handle; otherwise the DID they
    /// supplied). Empty string if resolution failed before a DID was
    /// determined.
    pub did: String,

    /// The bsky / atproto handle the caller supplied, if any. Echoed
    /// back so renderers can show "@creator.bsky.social" without
    /// re-resolving.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,

    /// Match / Mismatch / NotPublished / ResolutionFailed.
    pub status: AttestationStatus,

    /// On `Match`, the fingerprint that matched (full
    /// `sha256:<hex>`). `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_fingerprint: Option<String>,

    /// Human-readable detail. Always present on `ResolutionFailed`;
    /// usually present on `Mismatch` and `NotPublished`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Outcome of a neural-watermark detection pass, populated on
/// [`Report::watermark`] when the caller invoked the
/// `provcheck-watermark` detector. The check is independent of
/// C2PA — its purpose is to corroborate (or contradict) the
/// manifest using a signal that doesn't share the C2PA trust
/// chain.
///
/// Detector scope is named explicitly via [`WatermarkKind`] so a
/// renderer can say "silentcipher: detected" rather than the
/// vaguer "watermark detected" — useful because each detector
/// only finds watermarks embedded by its matching encoder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkResult {
    /// Which detector family ran. For now, always
    /// `SilentCipher`. New variants will arrive when additional
    /// detector families (AudioSeal, SynthID, …) are added.
    pub kind: WatermarkKind,

    /// Tri-state quality of the detection:
    ///
    /// - `Detected`     — confidence ≥ 0.70, structurally valid
    /// - `Degraded`     — 0.50 ≤ confidence < 0.70, structurally valid
    /// - `NotDetected`  — confidence < 0.50 OR no valid message structure
    ///
    /// The legacy boolean question "did we find a mark?" maps to
    /// `status != NotDetected`; the boolean is exposed for
    /// convenience as [`detected`](Self::detected).
    pub status: WatermarkStatus,

    /// Convenience boolean: `true` iff `status` is `Detected` OR
    /// `Degraded`. Renderers that only want a green/red answer
    /// can read this. `--require-watermark` on the CLI checks
    /// this field.
    pub detected: bool,

    /// Detector confidence in `[0.0, 1.0]`. Production renders
    /// land at 0.85–0.99. For unmarked input the back-end
    /// returns 0.0 as a sentinel (rather than the ~0.20 random
    /// floor) because we short-circuit on structural-validity
    /// failure before computing the confidence statistic.
    pub confidence: f32,

    /// Recovered payload bytes (5 bytes / 40 bits for
    /// silentcipher), populated whenever the message structure
    /// was valid — i.e. whenever `status != NotDetected`.
    /// Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,

    /// Recognised brand (issuer) of the watermark, parsed from
    /// the payload according to its schema version. `None` when
    /// the payload couldn't be parsed (unknown schema, or
    /// `status == NotDetected`). Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<WatermarkBrand>,

    /// Human-readable status detail. Used for non-detected
    /// outcomes that the renderer should distinguish from a
    /// real "not detected on audio" result — e.g. "not audio",
    /// "decoder error: …", "audio shorter than minimum
    /// detection window". Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Identifies which neural-watermark detector family produced
/// a [`WatermarkResult`]. Variants here are restricted to
/// FOSS-licensed detector families — see
/// `WATERMARK_LICENSE_POLICY.md` at the workspace root for the
/// admission rule and current pass/fail survey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkKind {
    /// Sony's silentcipher (Interspeech 2024). MIT-licensed
    /// code + weights. Implemented in `provcheck-watermark`.
    SilentCipher,
    /// Meta's AudioSeal (ICML 2024). MIT-licensed code + model
    /// weights (relicensed from CC-BY-NC to full MIT on
    /// 2024-04-02). Scaffolded in `provcheck-audioseal`.
    AudioSeal,
    /// WavMark (Chen et al., arXiv:2308.12770). MIT-licensed
    /// code, weights distributed via the `wavmark` PyPI
    /// package under the same terms. Scaffolded in
    /// `provcheck-wavmark`.
    WavMark,
}

/// Tri-state quality of a watermark detection. See
/// [`WatermarkResult::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkStatus {
    /// Confidence ≥ 0.70 and the recovered message is
    /// structurally valid. The watermark is present and the
    /// payload can be trusted.
    Detected,
    /// 0.50 ≤ confidence < 0.70. The message is structurally
    /// valid but some symbols disagreed across tiles — the file
    /// is most likely silentcipher-marked but the mark has been
    /// degraded (re-encoding, EQ, room recording, etc.) and the
    /// payload may be partially corrupted.
    Degraded,
    /// Either confidence < 0.50, or the recovered symbols did
    /// not form a valid silentcipher message (no terminator).
    /// Treated as "no mark present" by callers.
    NotDetected,
}

/// Recognised brand (issuer) of a watermark, parsed from the
/// payload bytes via the schema dispatch rules defined by
/// `provcheck-watermark`. The schema byte (currently always
/// at index 3) selects how the rest of the payload is
/// interpreted; today only schema 1 is in production use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum WatermarkBrand {
    /// rAIdio.bot — payload `RAI` (`[82, 65, 73]`).
    Raidio,
    /// doomscroll.fm — payload `DFM` (`[68, 70, 77]`).
    Doomscroll,
    /// vAIdeo.bot — payload `VAI` (`[86, 65, 73]`). Reserved
    /// for the video product when it joins the registry.
    Vaideo,
    /// Schema 1 payload with an ASCII brand code that isn't yet
    /// in the registry. The three letters are echoed back so
    /// the renderer can display them verbatim, but no name is
    /// assigned.
    UnknownAscii {
        /// The three ASCII bytes from payload positions 0..3.
        letters: [u8; 3],
    },
    /// Payload schema version isn't 1 — structure of the
    /// remaining bytes is detector-version-specific and we
    /// don't know how to interpret it. Raw payload is on
    /// [`WatermarkResult::payload`].
    UnknownSchema {
        /// The schema byte read from payload index 3.
        schema: u8,
    },
}

/// Tri-state-plus-failure status for DID-anchored attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// Signing certificate's fingerprint matches an active record
    /// under the resolved DID.
    Match,
    /// DID resolves and at least one active `app.provcheck.signingKey`
    /// record exists, but none match the signing certificate's
    /// fingerprint.
    Mismatch,
    /// DID resolves but the creator has no active
    /// `app.provcheck.signingKey` records.
    NotPublished,
    /// DID could not be resolved (handle didn't resolve, DID document
    /// unreachable, PDS unreachable, network failure, etc.).
    ResolutionFailed,
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
        if let Some(claim) = &self.identity {
            // Self-asserted identity from the asset's
            // app.provcheck.identity assertion. Render with an
            // explicit "claims" word so a reader doesn't confuse
            // it with the cryptographically-anchored did_attestation
            // below — the claim alone is never trust-anchoring.
            match &claim.handle {
                Some(h) => {
                    let _ = writeln!(f, "  claims identity: @{} ({})", h, claim.did);
                }
                None => {
                    let _ = writeln!(f, "  claims identity: {}", claim.did);
                }
            }
        }
        if let Some(att) = &self.did_attestation {
            // Identity label: prefer the handle for readability; fall
            // back to the DID. Both can be present; show DID alongside
            // when handle is also there.
            let label = match (&att.handle, att.did.as_str()) {
                (Some(h), did) if !did.is_empty() => format!("@{} ({})", h, did),
                (Some(h), _) => format!("@{}", h),
                (None, did) if !did.is_empty() => did.to_string(),
                (None, _) => "<no identity>".to_string(),
            };
            match att.status {
                AttestationStatus::Match => {
                    let _ = writeln!(f, "  attested by: {}", label);
                    if let Some(fp) = &att.matched_fingerprint {
                        let _ = writeln!(f, "    fingerprint: {}", fp);
                    }
                    if let Some(msg) = &att.message {
                        let _ = writeln!(f, "    label: {}", msg);
                    }
                }
                AttestationStatus::Mismatch => {
                    let _ = writeln!(f, "  attestation MISMATCH for: {}", label);
                    if let Some(msg) = &att.message {
                        let _ = writeln!(f, "    {}", msg);
                    }
                }
                AttestationStatus::NotPublished => {
                    let _ = writeln!(f, "  attestation: no signing-key records under {}", label);
                    if let Some(msg) = &att.message {
                        let _ = writeln!(f, "    {}", msg);
                    }
                }
                AttestationStatus::ResolutionFailed => {
                    let _ = writeln!(f, "  attestation UNAVAILABLE for: {}", label);
                    if let Some(msg) = &att.message {
                        let _ = writeln!(f, "    {}", msg);
                    }
                }
            }
        }
        if !self.watermarks.is_empty() {
            let _ = writeln!(f, "[watermarks]");
            for wm in &self.watermarks {
                let detector = match wm.kind {
                    WatermarkKind::SilentCipher => "silentcipher",
                    WatermarkKind::AudioSeal => "audioseal",
                    WatermarkKind::WavMark => "wavmark",
                };
                let pct = (wm.confidence.clamp(0.0, 1.0) * 100.0).round() as u32;
                match wm.status {
                    WatermarkStatus::Detected | WatermarkStatus::Degraded => {
                        let qualifier = match wm.status {
                            WatermarkStatus::Detected => "detected",
                            WatermarkStatus::Degraded => "detected (degraded)",
                            WatermarkStatus::NotDetected => unreachable!(),
                        };
                        let brand_label = wm
                            .brand
                            .as_ref()
                            .map(format_brand_label)
                            .unwrap_or_else(|| "<unknown brand>".to_string());
                        let _ = writeln!(
                            f,
                            "  {}: {} — {} ({}% confidence)",
                            detector, qualifier, brand_label, pct
                        );
                        if let Some(payload) = &wm.payload
                            && !payload.is_empty()
                        {
                            let hex: String =
                                payload.iter().map(|b| format!("{:02x}", b)).collect();
                            let _ = writeln!(f, "    payload: {}", hex);
                        }
                    }
                    WatermarkStatus::NotDetected => {
                        if let Some(msg) = &wm.message {
                            let _ = writeln!(f, "  {}: n/a ({})", detector, msg);
                        } else {
                            let _ = writeln!(f, "  {}: not detected", detector);
                        }
                    }
                }
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

fn format_brand_label(brand: &WatermarkBrand) -> String {
    match brand {
        WatermarkBrand::Raidio => "rAIdio.bot".to_string(),
        WatermarkBrand::Doomscroll => "doomscroll.fm".to_string(),
        WatermarkBrand::Vaideo => "vAIdeo.bot".to_string(),
        WatermarkBrand::UnknownAscii { letters } => {
            // Schema-1 brand triplet whose ASCII isn't in the
            // known registry. Surface the three letters so the
            // user can recognise a new product even before our
            // registry catches up — the payload bytes are still
            // shown verbatim on the line below for forensics.
            let s = std::str::from_utf8(letters).unwrap_or("???");
            format!("unrecognized source \"{}\"", s)
        }
        WatermarkBrand::UnknownSchema { schema } => {
            // Schema byte isn't 1 — the rest of the payload's
            // structure is opaque to this build of provcheck.
            // Detection itself is still valid; we just can't
            // identify the issuer or its conventions.
            format!("unrecognized payload schema (v{})", schema)
        }
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
