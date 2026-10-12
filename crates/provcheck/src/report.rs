use serde::{Deserialize, Serialize};

pub use provcheck_attestation_spec::IdentityClaim;

/// Content modality a provenance/watermark format applies to. Re-exported
/// from `provcheck-detect` so the unified format checklist and the
/// AI-content detectors speak the same modality vocabulary (`audio`,
/// `image`, `video`, `text` on the wire) instead of two parallel enums.
pub use provcheck_detect::DetectionFamily as Media;

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

    /// Tamper-evidence about the C2PA provenance LAYER itself, independent of
    /// signature validation of a present manifest. `Some(reason)` when there is
    /// positive evidence the provenance was removed or corrupted — currently a
    /// manifest box that is present but malformed/partial (a stripper that
    /// broke the box rather than cleanly removing it). `None` = no such
    /// evidence. Distinct from `validation_errors` (a PRESENT, parseable
    /// manifest failing its own hash/crypto checks) and from `unsigned` (no
    /// box at all). Surfaced as tamper-evidence in read/verify output.
    /// (Fork 2 F2.1: the C2PA-gap tamper detector.)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance_tamper: Option<String>,

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

    /// Unified format checklist: one typed row per provenance/watermark
    /// format provcheck knows how to look for, recording — for THIS asset —
    /// whether the format was found, absent, tampered, not-installed,
    /// not-applicable to the media, not-checked, or errored. This is the
    /// "check everything, click to make better" spine: it lets a caller
    /// render a single honest surface answering "here is what I could check
    /// on this machine, and here is what you can install to check more."
    ///
    /// Built by walking the capability registry (`crate::formats`) for the
    /// asset's media modality, then upgrading rows as C2PA verification, the
    /// watermark detectors, keyed shell-outs, and install-state resolution
    /// run. Superset in spirit of [`watermarks`](Self::watermarks) and
    /// [`detections`](Self::detections) (which stay populated for
    /// back-compat) but adds the crucial "attempted vs not-checked vs
    /// not-installed" distinction those vecs cannot express (a disabled or
    /// uninstalled family simply leaves no row there).
    ///
    /// Always empty from the core `verify_with_options` path — populated
    /// only by callers that ran the synthesis step. Omitted from JSON when
    /// empty (and defaults to empty on deserialise) so older outputs and
    /// builds that never synthesised a checklist produce identical output.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub checks: Vec<FormatCheck>,
}

/// One row in the unified format checklist ([`Report::checks`]). Records
/// the typed outcome of looking for a single provenance/watermark format on
/// one asset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormatCheck {
    /// Which format this row is about.
    pub id: FormatId,

    /// Media modalities the format applies to (e.g. `[image]` for TrustMark,
    /// `[image, video, audio]` for C2PA). Copied from the capability
    /// registry so a renderer can group or filter without re-deriving.
    pub media: Vec<Media>,

    /// Typed outcome for THIS asset.
    pub status: CheckStatus,

    /// Human-readable detail: the "why" behind the status — e.g. "box
    /// present but unparseable" for `Tampered`, "not audio" for
    /// `NotApplicable`, a decoder error for `Error`. Omitted from JSON when
    /// `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Detector confidence in `[0.0, 1.0]` when the status came from a
    /// probabilistic detector (watermark / AIGC). `None` for deterministic
    /// checks (C2PA present/absent) and for statuses where confidence is
    /// meaningless (`NotApplicable`, `NotChecked`, `NotInstalled`). Omitted
    /// from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    /// How to make this row checkable when `status == NotInstalled`: the
    /// operator-facing install hint (e.g. `provcheck --install trustmark`,
    /// or a note that the format is a paid DLC). Carried from the registry.
    /// Omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_hint: Option<String>,
}

/// Typed outcome of checking one format against one asset. Deliberately
/// richer than a boolean: the whole point of the checklist is to
/// distinguish "checked and absent" from "could not check" from "not
/// installed" from "wrong media". Models the same tri-state-plus-failure
/// spirit as [`provcheck_detect::DetectionStatus`], extended with the
/// install/checked distinctions the checklist needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckStatus {
    /// The format was found and validated on this asset (a C2PA manifest
    /// verified, a watermark detected, a keyed mark present).
    Present,
    /// The format was actively looked for and is NOT present (checked-absent
    /// — distinct from `NotChecked`).
    Absent,
    /// The format is present but shows positive tamper evidence (a manifest
    /// box present but malformed, a degraded/partial mark). Mirrors the
    /// `Report::provenance_tamper` signal at the row level.
    Tampered,
    /// This machine cannot check the format because its model/weights are
    /// not installed. `install_hint` says how to enable it. The "click to
    /// make better" row.
    NotInstalled,
    /// The format does not apply to this asset's media (e.g. an audio
    /// watermark on a still image). Not a failure — just out of scope.
    NotApplicable,
    /// The format applies and could be checked, but was not (user disabled
    /// it, or synthesis has not run the detector yet). Distinct from
    /// `Absent` (which means checked-and-not-found).
    NotChecked,
    /// The check was attempted but failed (decoder error, unreadable input
    /// for this format). `detail` carries the operator-facing reason.
    Error,
}

/// Every provenance / watermark / detector format provcheck knows how to
/// look for. Each variant maps to one row in the capability registry
/// (`crate::formats`). Adding a variant here plus a registry entry is how a
/// new format joins the checklist. Wire form is `snake_case`
/// (`c2pa`, `silent_cipher`, `synth_id_image`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FormatId {
    /// Embedded C2PA manifest (the primary provenance layer).
    C2pa,
    /// C2PA soft binding — a content fingerprint / watermark pointer that
    /// lets a stripped manifest be recovered from a manifest store (Durable
    /// Content Credentials). Read side is FOSS; the recovery service is a
    /// separate concern.
    SoftBinding,
    /// DID-anchored second-factor identity attestation
    /// (`app.provcheck.signingKey` cross-check).
    DidAttestation,
    /// Sony silentcipher audio watermark.
    SilentCipher,
    /// Meta AudioSeal audio watermark.
    AudioSeal,
    /// WavMark audio watermark.
    WavMark,
    /// Adobe/CAI TrustMark image watermark.
    TrustMark,
    /// TrustMark applied per-frame to video with a temporal vote.
    TrustMarkVideo,
    /// Meta VideoSeal native (temporal) video watermark.
    VideoSeal,
    /// Meta PixelSeal / ChunkySeal image watermark.
    PixelSeal,
    /// Google SynthID text watermark.
    SynthIdText,
    /// Google SynthID image watermark (detector access gated).
    SynthIdImage,
    /// Google SynthID audio watermark (detector access gated).
    SynthIdAudio,
    /// Google SynthID video watermark (detector access gated).
    SynthIdVideo,
    /// Backfire keyed image mark (BUSL; presence read via shell-out).
    Backfire,
    /// Mellin keyed audio serial (BUSL; presence read via shell-out).
    Mellin,
    /// AI-content / deepfake detection (paid DLC; probabilistic signal).
    AigcDetect,
}

impl FormatId {
    /// Stable lowercase identifier used in the human-readable checklist and
    /// as the argument to `provcheck --install <id>`. Matches the JSON wire
    /// form (`snake_case`).
    pub fn as_str(&self) -> &'static str {
        match self {
            FormatId::C2pa => "c2pa",
            FormatId::SoftBinding => "soft_binding",
            FormatId::DidAttestation => "did_attestation",
            FormatId::SilentCipher => "silent_cipher",
            FormatId::AudioSeal => "audio_seal",
            FormatId::WavMark => "wav_mark",
            FormatId::TrustMark => "trust_mark",
            FormatId::TrustMarkVideo => "trust_mark_video",
            FormatId::VideoSeal => "video_seal",
            FormatId::PixelSeal => "pixel_seal",
            FormatId::SynthIdText => "synth_id_text",
            FormatId::SynthIdImage => "synth_id_image",
            FormatId::SynthIdAudio => "synth_id_audio",
            FormatId::SynthIdVideo => "synth_id_video",
            FormatId::Backfire => "backfire",
            FormatId::Mellin => "mellin",
            FormatId::AigcDetect => "aigc_detect",
        }
    }
}

impl CheckStatus {
    /// Short human-readable label for the CLI `[formats]` section.
    pub fn label(&self) -> &'static str {
        match self {
            CheckStatus::Present => "present",
            CheckStatus::Absent => "absent",
            CheckStatus::Tampered => "TAMPERED",
            CheckStatus::NotInstalled => "not installed",
            CheckStatus::NotApplicable => "n/a",
            CheckStatus::NotChecked => "not checked",
            CheckStatus::Error => "error",
        }
    }

    /// Single-character glyph column for the checklist. ASCII only so the
    /// line stays paste-safe and legible in an 80-column terminal.
    pub fn glyph(&self) -> char {
        match self {
            CheckStatus::Present => '+',
            CheckStatus::Absent => '-',
            CheckStatus::Tampered => '!',
            CheckStatus::NotInstalled => ' ',
            CheckStatus::NotApplicable => '.',
            CheckStatus::NotChecked => '?',
            CheckStatus::Error => 'x',
        }
    }
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
/// [`Report::watermarks`] when the caller invoked the
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
                // No trust-store configured: stay quiet so the absent line reads as "not evaluated".
            }
        }
        if let Some(claim) = &self.identity {
            // Say "claims" — this self-asserted identity is never trust-anchoring, unlike did_attestation below.
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
                        let qualifier = if matches!(wm.status, WatermarkStatus::Degraded) {
                            "detected (degraded)"
                        } else {
                            "detected"
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
                            let mut hex = String::with_capacity(payload.len() * 2);
                            for b in payload {
                                use std::fmt::Write as _;
                                let _ = write!(hex, "{b:02x}");
                            }
                            let _ = writeln!(f, "    payload: {}", hex);
                        }
                        if let Some(regions) = &wm.marked_regions
                            && !regions.is_empty()
                        {
                            let _ = writeln!(f, "    marked: {}", format_regions(regions));
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
        if let Some(tamper) = &self.provenance_tamper {
            let _ = writeln!(f, "  tamper-evidence: {}", tamper);
        }

        if !self.checks.is_empty() {
            let _ = writeln!(f, "[formats]");
            let width = self
                .checks
                .iter()
                .map(|c| c.id.as_str().len())
                .max()
                .unwrap_or(0);
            for check in &self.checks {
                let _ = write!(
                    f,
                    "  [{}] {:width$}  {}",
                    check.status.glyph(),
                    check.id.as_str(),
                    check.status.label(),
                    width = width
                );
                if let Some(conf) = check.confidence {
                    let pct = (conf.clamp(0.0, 1.0) * 100.0).round() as u32;
                    let _ = write!(f, " ({}%)", pct);
                }
                let _ = writeln!(f);
                // A not-installed row shows its install hint on the sub-line; others show detail.
                if check.status == CheckStatus::NotInstalled
                    && let Some(hint) = &check.install_hint
                {
                    let _ = writeln!(f, "      install: {}", hint);
                } else if let Some(detail) = &check.detail {
                    let _ = writeln!(f, "      {}", detail);
                }
            }
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
        regions.iter().map(fmt_span).collect::<Vec<_>>().join(", ")
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
            // Surface the raw triplet so a new product is recognisable before the registry catches up.
            let s = std::str::from_utf8(letters).unwrap_or("???");
            format!("unrecognized source \"{}\"", s)
        }
        WatermarkBrand::UnknownSchema { schema } => {
            // Detection is valid but a non-1 schema leaves the issuer unidentifiable.
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
                let v_full = v.to_string();
                // Truncate on a char boundary: assertion values are arbitrary
                // UTF-8, so a byte-index slice could split a codepoint and panic.
                let v_short = if v_full.chars().count() > 200 {
                    format!("{}…", v_full.chars().take(200).collect::<String>())
                } else {
                    v_full
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
        // Pin the en-dash (U+2013): downstream parsers rely on it, so don't "normalise" to a hyphen.
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
        assert!(
            !json.contains("\"payload\""),
            "None payload should be omitted: {json}"
        );
    }

    #[test]
    fn watermark_result_omits_none_brand() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(
            !json.contains("\"brand\""),
            "None brand should be omitted: {json}"
        );
    }

    #[test]
    fn watermark_result_omits_none_message() {
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(
            !json.contains("\"message\""),
            "None message should be omitted: {json}"
        );
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
        // Pin the snake_case rename: downstream automation matches on these string values.
        let r = minimal_watermark_result();
        let json = serde_json::to_string(&r).expect("ser");
        assert!(
            json.contains("\"detected\""),
            "expected snake_case status, got: {json}"
        );
        let mut r2 = r.clone();
        r2.status = WatermarkStatus::Degraded;
        let json = serde_json::to_string(&r2).expect("ser");
        assert!(json.contains("\"status\":\"degraded\""), "got: {json}");
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
        // `tag = "code"` serialises brand as {"code": "raidio"}, not a bare string.
        assert!(
            json.contains("\"code\":\"raidio\""),
            "expected code-tagged brand, got: {json}"
        );
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
        // Back-compat: older outputs lack marked_regions; deserialise must default it to None.
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
            provenance_tamper: None,
            did_attestation: None,
            identity: None,
            parents: Vec::new(),
            watermarks: Vec::new(),
            detections: Vec::new(),
            checks: Vec::new(),
        }
    }

    #[test]
    fn exit_code_zero_when_verified() {
        let mut r = minimal_unsigned_report();
        r.verified = true;
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn provenance_tamper_surfaces_in_display_and_json() {
        let mut r = minimal_unsigned_report();
        assert!(!format!("{r}").contains("tamper-evidence"));
        assert!(
            !r.to_json_string()
                .expect("ser")
                .contains("provenance_tamper")
        );
        r.provenance_tamper = Some("box present but unparseable".into());
        let text = format!("{r}");
        assert!(
            text.contains("tamper-evidence:"),
            "human output shows the flag: {text}"
        );
        assert!(text.contains("box present but unparseable"));
        let json = r.to_json_string().expect("ser");
        assert!(
            json.contains("\"provenance_tamper\""),
            "JSON carries the flag: {json}"
        );
        let back: Report = serde_json::from_str(&json).expect("de");
        assert_eq!(
            back.provenance_tamper.as_deref(),
            Some("box present but unparseable")
        );
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
        assert!(json.contains("\"audio\""));
    }

    #[test]
    fn detections_default_deserialises_to_empty_on_legacy_report() {
        // Back-compat: a Report JSON without the detections field must deserialise to empty.
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
        assert_eq!(
            parsed.get("format").and_then(|v| v.as_str()),
            Some("audio/wav")
        );
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

#[cfg(test)]
mod format_check_tests {
    use super::*;

    fn minimal_report() -> Report {
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
            provenance_tamper: None,
            did_attestation: None,
            identity: None,
            parents: Vec::new(),
            watermarks: Vec::new(),
            detections: Vec::new(),
            checks: Vec::new(),
        }
    }

    #[test]
    fn empty_checks_omitted_from_json() {
        // Back-compat: an empty checklist must produce no `checks` key, matching old output byte-for-byte.
        let r = minimal_report();
        let json = r.to_json_string().expect("ser");
        assert!(
            !json.contains("\"checks\""),
            "empty checks must be omitted: {json}"
        );
    }

    #[test]
    fn checks_default_to_empty_on_legacy_input() {
        // Back-compat: a Report JSON without the checks field must deserialise to empty, not fail.
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
        assert!(r.checks.is_empty());
    }

    fn sample_check(id: FormatId, status: CheckStatus) -> FormatCheck {
        FormatCheck {
            id,
            media: vec![Media::Image],
            status,
            detail: None,
            confidence: None,
            install_hint: None,
        }
    }

    #[test]
    fn populated_checks_serialise_with_snake_case_ids() {
        let mut r = minimal_report();
        r.checks = vec![sample_check(FormatId::TrustMark, CheckStatus::Present)];
        let json = r.to_json_string().expect("ser");
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"trust_mark\""), "id snake_case: {json}");
        assert!(json.contains("\"present\""), "status snake_case: {json}");
    }

    #[test]
    fn format_id_wire_form_matches_as_str() {
        // JSON rename and as_str() must agree, or `provcheck --install <id>` won't match the JSON row.
        let json = serde_json::to_string(&FormatId::SynthIdImage).expect("ser");
        assert_eq!(json, "\"synth_id_image\"");
        assert_eq!(FormatId::SynthIdImage.as_str(), "synth_id_image");
    }

    #[test]
    fn check_status_wire_form_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::NotInstalled).expect("ser"),
            "\"not_installed\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::NotApplicable).expect("ser"),
            "\"not_applicable\""
        );
    }

    #[test]
    fn format_check_round_trips() {
        let mut c = sample_check(FormatId::AudioSeal, CheckStatus::NotInstalled);
        c.media = vec![Media::Audio];
        c.detail = Some("weights not cached".into());
        c.confidence = Some(0.0);
        c.install_hint = Some("provcheck --install audio_seal".into());
        let json = serde_json::to_string(&c).expect("ser");
        let back: FormatCheck = serde_json::from_str(&json).expect("de");
        assert_eq!(back, c);
    }

    #[test]
    fn display_renders_formats_section() {
        let mut r = minimal_report();
        r.checks = vec![
            sample_check(FormatId::C2pa, CheckStatus::Present),
            {
                let mut c = sample_check(FormatId::TrustMark, CheckStatus::NotInstalled);
                c.install_hint = Some("provcheck --install trust_mark".into());
                c
            },
            {
                let mut c = sample_check(FormatId::SilentCipher, CheckStatus::NotApplicable);
                c.detail = Some("not audio".into());
                c
            },
        ];
        let s = format!("{r}");
        assert!(s.contains("[formats]"), "section header missing: {s}");
        assert!(s.contains("c2pa"));
        assert!(s.contains("present"));
        assert!(
            s.contains("install: provcheck --install trust_mark"),
            "got: {s}"
        );
        assert!(s.contains("not audio"), "got: {s}");
        assert!(s.contains("[+]"), "present glyph: {s}");
        assert!(s.contains("[.]"), "n/a glyph: {s}");
    }

    #[test]
    fn display_omits_formats_section_when_empty() {
        let r = minimal_report();
        let s = format!("{r}");
        assert!(!s.contains("[formats]"), "no section for empty checks: {s}");
    }

    #[test]
    fn display_renders_confidence_when_present() {
        let mut r = minimal_report();
        let mut c = sample_check(FormatId::TrustMark, CheckStatus::Present);
        c.confidence = Some(0.87);
        r.checks = vec![c];
        let s = format!("{r}");
        assert!(s.contains("(87%)"), "confidence rendered: {s}");
    }
}
