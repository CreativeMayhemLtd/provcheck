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

    /// Provenance chain — parent manifests (relationship: parentOf)
    /// of the active manifest. Populated when the signed file
    /// declares prior provenance via C2PA ingredients. The first
    /// entry is the direct parent; deeper entries (if any) are
    /// grandparents.
    ///
    /// The publisher-attestation flow produces files with a parent
    /// chain: e.g. a doomscroll.fm video signed by doomscroll
    /// (creator), then re-signed by a publisher (active manifest
    /// → action c2pa.published, parentOf → doomscroll's manifest).
    /// Verifiers render this chain so the audience sees "published
    /// by X, originally created by Y."
    ///
    /// Omitted from JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub parents: Vec<ParentManifest>,

    /// Neural-watermark detection results. Always empty from
    /// the core `verify_with_options` path — populated only by
    /// callers that invoked one or more detectors. The shipped
    /// detector families are: silentcipher (audio, 44.1 kHz)
    /// in `provcheck-watermark`, AudioSeal (audio, 16 kHz) in
    /// `provcheck-audioseal`, WavMark (audio, 16 kHz) in
    /// `provcheck-wavmark`, TrustMark-B (image) in
    /// `provcheck-image`, per-frame TrustMark + temporal vote
    /// (video) in `provcheck-video`, and SynthID-text
    /// (Bayesian tournament-sampling) in
    /// `provcheck-synthid-text`. Callers push results into
    /// this vec.
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

    /// AI-content detection results from the v0.9 detector
    /// dispatch slot. Always empty from the core
    /// `verify_with_options` path — populated only by callers
    /// that registered detectors via
    /// [`provcheck_detect::DetectorRegistry`] and ran them
    /// against the asset.
    ///
    /// Distinct from [`watermarks`](Self::watermarks): watermark
    /// detectors find marks the producer deliberately embedded
    /// at generation time; AI-content detectors classify content
    /// that may not carry any watermark (deepfake / anti-spoofing
    /// / synthetic-voice classifiers). Both vectors can populate
    /// independently for the same asset.
    ///
    /// provcheck ships NO bundled detector model. The
    /// `provcheck-detect` crate provides the trait + dispatch
    /// types; concrete detectors land via:
    /// - **Paid DLC packs** (Creative Mayhem-distributed after
    ///   v1.0; first pack sourced from the doomscroll.fm
    ///   pipeline).
    /// - **Operator-supplied open-source detectors** wrapped via
    ///   the public [`provcheck_detect::Detector`] trait.
    ///
    /// Omitted from JSON when empty so a build with no
    /// registered detectors produces the same output as a build
    /// with the slot disabled.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub detections: Vec<provcheck_detect::DetectionResult>,
}

/// A single parent manifest in the active manifest's chain. Each
/// entry is one level deeper in the lineage — index 0 is the
/// direct parent of the active manifest, index 1 is its parent,
/// and so on (if multiple levels are present in the manifest
/// store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentManifest {
    /// Manifest label (e.g. `urn:c2pa:fa479510-…`). Used by
    /// renderers as a stable identifier.
    pub label: String,

    /// Signer name (certificate subject CN or issuer) of the
    /// parent manifest, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,

    /// `claim_generator` of the parent (e.g. `Doomscroll.fm/0.1.0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator: Option<String>,

    /// `title` claim of the parent manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Self-asserted identity claim from the parent manifest's
    /// `app.provcheck.identity` assertion, if present. Lets a
    /// renderer show "originally created by @creator.bsky.social"
    /// for files whose parent was signed through provcheck-kit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityClaim>,
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
    /// Which detector family ran. Six variants currently ship:
    /// `SilentCipher`, `AudioSeal`, `WavMark`, `TrustMark`,
    /// `TrustMarkVideo`, and `SynthIdText`.
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

    /// Optional time-spans (in seconds, `(start, end)`) where the
    /// watermark is detected. Populated by all three detectors
    /// (silentcipher derives spans from per-tile match-fraction
    /// against the global mode; AudioSeal and WavMark from
    /// per-sample / per-window presence). `None` when nothing was
    /// detected or the audio was too short for any tile/window to
    /// land cleanly inside a marked stretch. Omitted from JSON
    /// when `None`.
    ///
    /// Backward-compatible serde: defaults to `None` on deserialise
    /// so older verifier outputs without this field still parse.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub marked_regions: Option<Vec<(f32, f32)>>,
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
    /// 2024-04-02). Implemented in `provcheck-audioseal`.
    AudioSeal,
    /// WavMark (Chen et al., arXiv:2308.12770). MIT-licensed
    /// code, weights distributed via the `wavmark` PyPI
    /// package under the same terms. Implemented in
    /// `provcheck-wavmark`.
    WavMark,
    /// TrustMark (Adobe / CAI, arXiv:2311.18297). MIT-licensed
    /// code and weights, BCH-5 ecosystem interop with the
    /// upstream Python TrustMark, image-modality wired through
    /// `ort`. Implemented in `provcheck-image`.
    TrustMark,
    /// TrustMark applied per-frame to a video, with temporal
    /// majority-vote across the recovered brand ids.
    /// Implemented in `provcheck-video` via ffmpeg shell-out.
    TrustMarkVideo,
    /// Google SynthID-text. Tournament-sampling Bayesian
    /// detection over LLM-sampled tokens; pure-Rust SHA256
    /// hash + Abramowitz-Stegun erf approximation for the
    /// confidence transform. Apache-2.0 algorithm. Implemented
    /// in `provcheck-synthid-text`.
    SynthIdText,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// assigned. This variant is silentcipher-specific (40-bit
    /// payload + ASCII triplet convention).
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
    /// Numeric-registry brand identifier (16-bit big-endian)
    /// that isn't yet in the registry. Used by short-payload
    /// detectors like AudioSeal (16 bits) and WavMark (32
    /// bits — lower 16 used as brand ID) where the ASCII
    /// convention doesn't fit. See `docs/brand-registry.md`.
    UnknownNumeric {
        /// The 16-bit brand identifier read from the payload.
        id: u16,
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
                    WatermarkKind::TrustMark => "trustmark",
                    WatermarkKind::TrustMarkVideo => "trustmark-video",
                    WatermarkKind::SynthIdText => "synthid-text",
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
                        if let Some(regions) = &wm.marked_regions
                            && !regions.is_empty()
                        {
                            let _ =
                                writeln!(f, "    marked: {}", format_regions(regions));
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

/// Render a list of `(start_sec, end_sec)` spans as a compact
/// human-readable string: `0:02–0:14, 0:21–0:58`. Times under one
/// hour use `M:SS`; longer files use `H:MM:SS`. If more than four
/// regions are present, the rendering truncates with an ellipsis
/// (`0:02–0:14, …, 1:42–2:01 (7 regions)`) so the line stays
/// scannable in the text report.
fn format_regions(regions: &[(f32, f32)]) -> String {
    fn fmt_time(t: f32) -> String {
        let total = t.max(0.0) as u64;
        let h = total / 3600;
        let m = (total % 3600) / 60;
        let s = total % 60;
        if h > 0 {
            format!("{h}:{m:02}:{s:02}")
        } else {
            format!("{m}:{s:02}")
        }
    }
    fn fmt_span((a, b): &(f32, f32)) -> String {
        format!("{}\u{2013}{}", fmt_time(*a), fmt_time(*b))
    }

    let n = regions.len();
    if n <= 4 {
        regions
            .iter()
            .map(fmt_span)
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        let head = fmt_span(&regions[0]);
        let tail = fmt_span(&regions[n - 1]);
        format!("{head}, …, {tail} ({n} regions)")
    }
}

fn format_brand_label(brand: &WatermarkBrand) -> String {
    match brand {
        WatermarkBrand::Raidio => "rAIdio.bot".to_string(),
        WatermarkBrand::Doomscroll => "doomscroll.fm".to_string(),
        WatermarkBrand::Vaideo => "vAIdeo.bot".to_string(),
        WatermarkBrand::UnknownNumeric { id } => {
            format!("unknown brand (id 0x{id:04x})")
        }
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

#[cfg(test)]
mod tests {
    use super::format_regions;

    #[test]
    fn format_regions_short_list_inline() {
        let regs = vec![(2.0, 14.0), (21.0, 58.0)];
        assert_eq!(format_regions(&regs), "0:02\u{2013}0:14, 0:21\u{2013}0:58");
    }

    #[test]
    fn format_regions_uses_hms_past_one_hour() {
        let regs = vec![(0.0, 3725.0)];
        assert_eq!(format_regions(&regs), "0:00\u{2013}1:02:05");
    }

    #[test]
    fn format_regions_uses_en_dash_not_hyphen() {
        // Pin the en-dash (U+2013) — display convention across
        // every region range. A future maintainer who "normalises"
        // it to a hyphen would invalidate downstream parsers.
        let regs = vec![(2.0, 14.0)];
        let s = format_regions(&regs);
        assert!(s.contains('\u{2013}'), "expected en-dash in {s}");
        assert!(!s.contains('-'), "expected no hyphen in {s}");
    }

    #[test]
    fn format_regions_empty_list_produces_empty_output() {
        assert_eq!(format_regions(&[]), "");
    }

    #[test]
    fn format_regions_truncates_long_lists() {
        let regs = vec![
            (0.0, 5.0),
            (10.0, 15.0),
            (20.0, 25.0),
            (30.0, 35.0),
            (40.0, 45.0),
            (50.0, 55.0),
            (60.0, 65.0),
        ];
        let s = format_regions(&regs);
        assert!(s.starts_with("0:00\u{2013}0:05"));
        assert!(s.contains("1:00\u{2013}1:05"));
        assert!(s.contains("(7 regions)"));
        assert!(s.contains('\u{2026}'), "expected ellipsis: {s}");
    }
}

#[cfg(test)]
mod watermark_result_serialization_tests {
    use super::*;

    fn minimal_watermark_result() -> WatermarkResult {
        WatermarkResult {
            kind: WatermarkKind::SilentCipher,
            status: WatermarkStatus::Detected,
            detected: true,
            confidence: 0.95,
            payload: None,
            brand: None,
            message: None,
            marked_regions: None,
        }
    }

    #[test]
    fn watermark_result_serialises_required_fields() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"detected\""));
        assert!(json.contains("\"confidence\""));
    }

    #[test]
    fn watermark_result_omits_none_payload() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(!json.contains("\"payload\""), "None payload should be omitted: {json}");
    }

    #[test]
    fn watermark_result_omits_none_brand() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(!json.contains("\"brand\""), "None brand should be omitted: {json}");
    }

    #[test]
    fn watermark_result_omits_none_message() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(!json.contains("\"message\""), "None message should be omitted: {json}");
    }

    #[test]
    fn watermark_result_omits_none_marked_regions() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(
            !json.contains("\"marked_regions\""),
            "None marked_regions should be omitted: {json}"
        );
    }

    #[test]
    fn watermark_result_serialises_populated_payload() {
        let mut r = minimal_watermark_result();
        r.payload = Some(vec![0x52, 0x41, 0x49, 0x01, 0x00]);
        let json = serde_json::to_string(&r).expect("ser");
        assert!(json.contains("\"payload\""));
    }

    #[test]
    fn watermark_status_uses_snake_case_on_wire() {
        // Pin the snake_case rename — automation downstream may
        // match on the string values.
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(json.contains("\"detected\""), "expected snake_case status, got: {json}");
        // Now degraded path.
        let mut r2 = r.clone();
        r2.status = WatermarkStatus::Degraded;
        let json = serde_json::to_string(&r2).expect("ser");
        assert!(json.contains("\"status\":\"degraded\""), "got: {json}");
        // Now not_detected — must use underscore, not camelCase
        // or kebab-case.
        let mut r3 = r.clone();
        r3.status = WatermarkStatus::NotDetected;
        let json = serde_json::to_string(&r3).expect("ser");
        assert!(json.contains("\"status\":\"not_detected\""), "got: {json}");
    }

    #[test]
    fn watermark_kind_uses_snake_case_on_wire() {
        let mut r = minimal_watermark_result();
        r.kind = WatermarkKind::TrustMarkVideo;
        let json = serde_json::to_string(&r).expect("ser");
        assert!(
            json.contains("\"kind\":\"trust_mark_video\""),
            "expected snake_case kind, got: {json}"
        );
    }

    #[test]
    fn watermark_brand_serialises_with_code_tag() {
        let mut r = minimal_watermark_result();
        r.brand = Some(WatermarkBrand::Raidio);
        let json = serde_json::to_string(&r).expect("ser");
        // The `tag = "code"` serde attr means brand serialises as
        // {"code": "raidio"} not as a bare string.
        assert!(json.contains("\"code\":\"raidio\""), "expected code-tagged brand, got: {json}");
    }

    #[test]
    fn watermark_result_round_trips_through_serde() {
        let mut r = minimal_watermark_result();
        r.payload = Some(vec![1, 2, 3, 4, 5]);
        r.brand = Some(WatermarkBrand::Doomscroll);
        r.message = Some("test message".into());
        r.marked_regions = Some(vec![(1.0, 2.5), (5.0, 7.5)]);
        let json = serde_json::to_string(&r).expect("ser");
        let back: WatermarkResult = serde_json::from_str(&json).expect("de");
        assert_eq!(back.payload, r.payload);
        assert_eq!(back.brand, r.brand);
        assert_eq!(back.message, r.message);
        assert_eq!(back.marked_regions, r.marked_regions);
    }

    #[test]
    fn watermark_result_marked_regions_defaults_to_none_on_legacy_input() {
        // Backward-compat: older verifier outputs lacked the
        // marked_regions field. Deserialise must default it to
        // None rather than failing.
        let legacy = r#"{
            "kind": "silent_cipher",
            "status": "detected",
            "detected": true,
            "confidence": 0.9
        }"#;
        let r: WatermarkResult = serde_json::from_str(legacy).expect("legacy parse");
        assert!(r.marked_regions.is_none());
    }
}

#[cfg(test)]
mod report_serialization_tests {
    use super::*;

    fn minimal_unsigned_report() -> Report {
        Report {
            verified: false,
            unsigned: true,
            trusted: None,
            failure_reason: None,
            active_manifest: None,
            signer: None,
            signed_at: None,
            claim_generator: None,
            assertions: serde_json::Value::Null,
            ingredient_count: 0,
            format: None,
            validation_errors: 0,
            did_attestation: None,
            identity: None,
            parents: Vec::new(),
            watermarks: Vec::new(),
            detections: Vec::new(),
        }
    }

    #[test]
    fn exit_code_zero_when_verified() {
        let mut r = minimal_unsigned_report();
        r.verified = true;
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn exit_code_one_when_not_verified() {
        let r = minimal_unsigned_report();
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn to_json_string_produces_pretty_indented_output() {
        let r = minimal_unsigned_report();
        let json = r.to_json_string().expect("ser");
        // Pretty-printed → contains newlines + indentation.
        assert!(json.contains('\n'));
        assert!(json.contains("  "));
    }

    #[test]
    fn to_json_string_includes_verified_field() {
        let r = minimal_unsigned_report();
        let json = r.to_json_string().expect("ser");
        assert!(json.contains("\"verified\""));
    }

    #[test]
    fn to_json_string_omits_empty_watermarks_vec() {
        // watermarks: skip_serializing_if = "Vec::is_empty" per
        // the field doc — empty vec must not produce a key.
        let r = minimal_unsigned_report();
        let json = r.to_json_string().expect("ser");
        assert!(
            !json.contains("\"watermarks\""),
            "empty watermarks must be omitted: {json}"
        );
    }

    #[test]
    fn to_json_string_omits_empty_parents_vec() {
        let r = minimal_unsigned_report();
        let json = r.to_json_string().expect("ser");
        assert!(
            !json.contains("\"parents\""),
            "empty parents must be omitted: {json}"
        );
    }

    #[test]
    fn to_json_string_omits_empty_detections_vec() {
        // v0.9.72: detections is empty for the offline verify
        // path. Pin the skip_serializing_if invariant.
        let r = minimal_unsigned_report();
        let json = r.to_json_string().expect("ser");
        assert!(
            !json.contains("\"detections\""),
            "empty detections must be omitted: {json}"
        );
    }

    #[test]
    fn populated_detections_serialise_under_detections_key() {
        let mut r = minimal_unsigned_report();
        r.detections = vec![provcheck_detect::DetectionResult {
            detector: "test-detector".into(),
            family: provcheck_detect::DetectionFamily::Audio,
            status: provcheck_detect::DetectionStatus::NotDetected,
            detected: false,
            confidence: 0.1,
            model_id: None,
            version: None,
            message: None,
        }];
        let json = r.to_json_string().expect("ser");
        assert!(json.contains("\"detections\""));
        assert!(json.contains("test-detector"));
        // family snake_case pinned
        assert!(json.contains("\"audio\""));
    }

    #[test]
    fn detections_default_deserialises_to_empty_on_legacy_report() {
        // Backward-compat: a JSON Report from before v0.9.72
        // (no `detections` field) must deserialise with an
        // empty detections vec.
        let legacy = r#"{
            "verified": false,
            "unsigned": true,
            "trusted": null,
            "failure_reason": null,
            "active_manifest": null,
            "signer": null,
            "signed_at": null,
            "claim_generator": null,
            "assertions": null,
            "ingredient_count": 0,
            "format": null,
            "validation_errors": 0
        }"#;
        let r: Report = serde_json::from_str(legacy).expect("legacy parse");
        assert!(r.detections.is_empty());
    }

    #[test]
    fn to_json_string_round_trips_through_serde_json() {
        let mut r = minimal_unsigned_report();
        r.verified = true;
        r.format = Some("audio/wav".into());
        let json = r.to_json_string().expect("ser");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.get("verified").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(parsed.get("format").and_then(|v| v.as_str()), Some("audio/wav"));
    }

    #[test]
    fn display_includes_unsigned_marker_for_unsigned_report() {
        let r = minimal_unsigned_report();
        let s = format!("{r}");
        assert!(s.contains("[UNSIGNED]"), "got: {s}");
    }

    #[test]
    fn display_includes_verified_marker_for_verified_report() {
        let mut r = minimal_unsigned_report();
        r.verified = true;
        r.unsigned = false;
        let s = format!("{r}");
        assert!(s.contains("[VERIFIED]"), "got: {s}");
    }

    #[test]
    fn display_includes_invalid_marker_when_not_verified_and_not_unsigned() {
        let mut r = minimal_unsigned_report();
        r.verified = false;
        r.unsigned = false;
        let s = format!("{r}");
        assert!(s.contains("[INVALID]"), "got: {s}");
    }

    #[test]
    fn display_includes_failure_reason_when_present() {
        let mut r = minimal_unsigned_report();
        r.failure_reason = Some("test failure reason".into());
        let s = format!("{r}");
        assert!(s.contains("test failure reason"), "got: {s}");
    }
}
