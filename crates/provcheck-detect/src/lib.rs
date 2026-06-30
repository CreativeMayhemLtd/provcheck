//! AI-content detection trait for provcheck.
//!
//! Defines the **contract** operators implement against to plug in
//! their own deepfake / anti-spoofing / AI-generated-content
//! classifier. This crate is **FOSS Apache-2.0 plumbing only** and
//! ships **no model weights**. Detector models are bring-your-own:
//!
//! - **Commercial paid-DLC packs** (Creative Mayhem-distributed):
//!   ship as a paid DLC layer after v1.0. The first such pack is
//!   sourced from the doomscroll.fm pipeline and is NOT in this
//!   public repo at any version.
//! - **Operator-supplied open-source detectors**: the operator
//!   wraps an existing FOSS detector (e.g. an audio-deepfake
//!   classifier from a research group) by implementing this trait.
//!   provcheck does not bundle those FOSS models either.
//!
//! Distinction from `provcheck-watermark` + friends: this crate is
//! for detecting AI-generated content that does NOT carry an
//! embedded watermark. The watermark crates (silentcipher,
//! AudioSeal, WavMark, TrustMark image+video, SynthID-text) only
//! fire on content that was deliberately marked at generation time
//! by a cooperating producer; they ARE shipped FOSS by provcheck.
//! Deepfake detection is the complement: "is this content
//! AI-generated even without a watermark?"
//!
//! ## Detector trait
//!
//! Implementors provide:
//!
//! 1. A name (used in the dispatch + report layer).
//! 2. The set of modalities the detector covers
//!    (`DetectionFamily::Audio | Video | Image | Text`).
//! 3. A `run(...)` method that takes a slice of bytes from the
//!    asset (the verifier loads the file) and returns a
//!    [`DetectionResult`].
//!
//! The verifier dispatches across registered detectors in
//! registration order; each is called independently, errors are
//! per-detector (not fatal), and results land in
//! `Report::detections`.
//!
//! ## Public spec
//!
//! This trait is the public extension point for ecosystem
//! integrators. Implementations live downstream of this crate
//! (in operator code, in DLC packs, or in third-party adapter
//! crates). The contract is:
//!
//! - The trait is `Send + Sync` so the verifier can call it from
//!   any thread without per-detector locking.
//! - The trait is object-safe so `Vec<Box<dyn Detector>>` works.
//! - `DetectionResult` is `Serialize + Deserialize` so the
//!   verifier's `--json` output can include it.
//! - `DetectionFamily` is `Copy + Eq + Hash + Serialize +
//!   Deserialize` so dispatch can filter by modality.
//!
//! See `docs/public-api-stability.md` for the stability contract
//! and `docs/v0.9-roadmap/README.md` section 9a + 9b for the
//! design rationale.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Which content modality a detector covers. A detector may cover
/// more than one (a multimodal classifier might cover Audio + Video
/// over the same MP4 input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionFamily {
    /// Audio content (mp3, wav, m4a, etc.)
    Audio,
    /// Image content (png, jpg, webp, etc.)
    Image,
    /// Video content (mp4, mov, mkv, etc.)
    Video,
    /// Text content (txt, md, html, etc.)
    Text,
}

/// Verdict tier from a detector. Mirrors the
/// [`provcheck::report::WatermarkStatus`] tier semantics used by
/// the watermark detectors so renderers can treat watermark and
/// AI-detection results uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    /// High-confidence detection: the detector is confident the
    /// content is AI-generated.
    Detected,
    /// Borderline detection: confidence in the documented degraded
    /// band ([0.50, 0.70) for detectors that adopt the canonical
    /// `provcheck::confidence` thresholds).
    Degraded,
    /// No detection: confidence below the degraded floor OR the
    /// detector returned an explicit "not AI-generated" verdict.
    NotDetected,
    /// The detector ran but the input modality, format, or duration
    /// was outside its supported range. Distinct from `NotDetected`
    /// so the renderer can distinguish "AI-generated: NO" from
    /// "we did not check".
    NotApplicable,
    /// The detector failed (model not loaded, file unreadable for
    /// the detector's specific format expectations, internal
    /// error). Carries an operator-facing message.
    Error,
}

/// A single detector's verdict for a single input asset.
///
/// `family` MUST be one of the detector's declared modalities (a
/// detector that claims Audio cannot return `family = Video`). The
/// dispatch layer enforces this with a debug assertion; in release
/// the field is treated as advisory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Name of the detector that produced this result. Matches
    /// [`Detector::name`] of the implementor.
    pub detector: String,
    /// Modality the detector evaluated.
    pub family: DetectionFamily,
    /// Verdict tier.
    pub status: DetectionStatus,
    /// Convenience boolean: true iff `status == Detected ||
    /// status == Degraded`. Mirrors `WatermarkResult::detected`.
    pub detected: bool,
    /// Confidence in `[0.0, 1.0]`. For `NotApplicable` or `Error`
    /// the value is 0.0 sentinel (mirrors watermark NotDetected).
    pub confidence: f32,
    /// Opaque model identifier. Operators wrapping a downstream
    /// detector populate this with their model's version /
    /// checkpoint identifier so the renderer can show which model
    /// produced which verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    /// Detector implementation version (semver).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Human-readable detail. Always present on `Error` and
    /// `NotApplicable`; optional on the verdict tiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Error a detector can surface during its `run`. Implementors
/// return `Err(DetectorError::*)` to signal a hard failure;
/// soft-fail cases (input outside the detector's supported range)
/// return `Ok(DetectionResult { status: NotApplicable, ... })` so
/// the dispatch layer can route them differently from real
/// runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// The detector's model is not installed. The operator action
    /// is to either install the paid DLC, or supply a path /
    /// configuration that points at an existing FOSS model.
    #[error("detector {detector} model not installed: {hint}")]
    ModelNotInstalled {
        /// Name of the detector reporting the missing model.
        detector: String,
        /// Operator-facing hint for how to install the model.
        hint: String,
    },

    /// The detector's model loaded but its inference call failed.
    /// Distinguished from `ModelNotInstalled` so the dispatch
    /// layer can keep going (a future asset MIGHT work).
    #[error("detector {detector} inference failed: {reason}")]
    Inference {
        /// Name of the detector reporting the failure.
        detector: String,
        /// Operator-facing failure reason.
        reason: String,
    },

    /// IO failure reading the asset bytes. Distinct from
    /// `Inference` so the renderer can route this to a
    /// disk-level diagnostic.
    #[error("detector {detector} io: {source}")]
    Io {
        /// Name of the detector that hit the IO error.
        detector: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
}

/// The detector contract. Implementations are `Send + Sync` so the
/// verifier's dispatch layer can call them from any thread.
///
/// Per-detector instances should be cheap to construct; the
/// dispatch layer holds them in a `Vec<Box<dyn Detector>>` and
/// keeps them alive across multiple verify calls. If the underlying
/// model is expensive to load, the implementation should lazy-load
/// it on first `run`, not in the constructor.
pub trait Detector: Send + Sync {
    /// Detector name. Used as the `DetectionResult::detector`
    /// field and in operator-facing log lines. Should be stable
    /// across versions of the implementation so downstream
    /// filtering works.
    fn name(&self) -> &str;

    /// The modalities this detector covers. The dispatch layer
    /// uses this to skip detectors whose declared families don't
    /// match the asset's apparent modality.
    fn families(&self) -> &[DetectionFamily];

    /// Run the detector against an asset already loaded into
    /// `bytes`. The dispatch layer loads the file once and hands
    /// the slice to every registered detector to avoid N reads
    /// for N detectors.
    ///
    /// Returns `Ok` for normal verdicts (`Detected` / `Degraded`
    /// / `NotDetected` / `NotApplicable`) and for the "tried but
    /// the model said no, here's why" case. Reserves `Err` for
    /// hard failures the operator needs to know about
    /// (`ModelNotInstalled`, `Inference`, `Io`).
    fn run(&self, bytes: &[u8]) -> Result<DetectionResult, DetectorError>;
}

/// Dispatch layer: a registry of detectors that runs them all
/// against an asset and collects the results. The verifier's
/// `Report` carries a `Vec<DetectionResult>`; this struct is what
/// populates that vector.
///
/// Construction is `Default::default()` for an empty registry;
/// add detectors via [`Self::register`]. Order matters: the
/// dispatch runs detectors in registration order, and the
/// resulting `Vec<DetectionResult>` reflects that order.
#[derive(Default)]
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a detector. Order matters: the first registered
    /// detector runs first.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// True if no detectors are registered.
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run every registered detector against `bytes` and collect
    /// the results. Detectors that return `Err` are projected onto
    /// `DetectionResult { status: Error, ... }` so the caller
    /// gets a uniform vector to render. The dispatch layer never
    /// short-circuits on a single detector's failure.
    pub fn run_all(&self, bytes: &[u8]) -> Vec<DetectionResult> {
        self.detectors
            .iter()
            .map(|d| match d.run(bytes) {
                Ok(r) => r,
                Err(e) => DetectionResult {
                    detector: d.name().to_string(),
                    family: d
                        .families()
                        .first()
                        .copied()
                        .unwrap_or(DetectionFamily::Audio),
                    status: DetectionStatus::Error,
                    detected: false,
                    confidence: 0.0,
                    model_id: None,
                    version: None,
                    message: Some(format!("{e}")),
                },
            })
            .collect()
    }
}

impl std::fmt::Debug for DetectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectorRegistry")
            .field("len", &self.detectors.len())
            .field(
                "detectors",
                &self
                    .detectors
                    .iter()
                    .map(|d| d.name().to_string())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test detector that always reports `NotDetected` with a
    /// fixed confidence. Exercises the trait without depending on
    /// any real model.
    struct AlwaysNegative {
        name: &'static str,
        families: Vec<DetectionFamily>,
        confidence: f32,
    }

    impl Detector for AlwaysNegative {
        fn name(&self) -> &str {
            self.name
        }

        fn families(&self) -> &[DetectionFamily] {
            &self.families
        }

        fn run(&self, _bytes: &[u8]) -> Result<DetectionResult, DetectorError> {
            Ok(DetectionResult {
                detector: self.name.to_string(),
                family: self.families[0],
                status: DetectionStatus::NotDetected,
                detected: false,
                confidence: self.confidence,
                model_id: Some("test-model-1".into()),
                version: Some("0.1.0".into()),
                message: None,
            })
        }
    }

    /// A test detector that always errors. Exercises the Error
    /// projection path in the dispatch layer.
    struct AlwaysModelMissing {
        name: &'static str,
    }

    impl Detector for AlwaysModelMissing {
        fn name(&self) -> &str {
            self.name
        }

        fn families(&self) -> &[DetectionFamily] {
            &[DetectionFamily::Audio]
        }

        fn run(&self, _bytes: &[u8]) -> Result<DetectionResult, DetectorError> {
            Err(DetectorError::ModelNotInstalled {
                detector: self.name.to_string(),
                hint: "install via `kit dlc install detectobot` (paid pack) \
                       OR implement Detector against an open-source classifier"
                    .into(),
            })
        }
    }

    // ----- DetectionFamily serde ----------

    #[test]
    fn detection_family_serialises_snake_case() {
        let s = serde_json::to_string(&DetectionFamily::Audio).expect("ser");
        assert_eq!(s, "\"audio\"");
        let s = serde_json::to_string(&DetectionFamily::Video).expect("ser");
        assert_eq!(s, "\"video\"");
    }

    #[test]
    fn detection_family_is_copy_eq_hash() {
        // Compile-time assertion via trait bounds.
        fn assert_traits<T: Copy + Eq + std::hash::Hash>() {}
        assert_traits::<DetectionFamily>();
        let a = DetectionFamily::Audio;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ----- DetectionStatus serde ----------

    #[test]
    fn detection_status_serialises_snake_case() {
        let s = serde_json::to_string(&DetectionStatus::Detected).expect("ser");
        assert_eq!(s, "\"detected\"");
        let s = serde_json::to_string(&DetectionStatus::NotApplicable).expect("ser");
        assert_eq!(s, "\"not_applicable\"");
        let s = serde_json::to_string(&DetectionStatus::NotDetected).expect("ser");
        assert_eq!(s, "\"not_detected\"");
    }

    // ----- DetectionResult serde ----------

    #[test]
    fn detection_result_omits_none_fields() {
        let r = DetectionResult {
            detector: "test".into(),
            family: DetectionFamily::Audio,
            status: DetectionStatus::NotDetected,
            detected: false,
            confidence: 0.1,
            model_id: None,
            version: None,
            message: None,
        };
        let json = serde_json::to_string(&r).expect("ser");
        assert!(!json.contains("model_id"));
        assert!(!json.contains("version"));
        assert!(!json.contains("message"));
    }

    #[test]
    fn detection_result_round_trips() {
        let r = DetectionResult {
            detector: "test".into(),
            family: DetectionFamily::Video,
            status: DetectionStatus::Detected,
            detected: true,
            confidence: 0.95,
            model_id: Some("model-v2".into()),
            version: Some("1.0.0".into()),
            message: Some("test message".into()),
        };
        let json = serde_json::to_string(&r).expect("ser");
        let back: DetectionResult = serde_json::from_str(&json).expect("de");
        assert_eq!(back, r);
    }

    // ----- DetectorError display ----------

    #[test]
    fn model_not_installed_display_includes_detector_and_hint() {
        let e = DetectorError::ModelNotInstalled {
            detector: "test-det".into(),
            hint: "install thing".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("test-det"));
        assert!(s.contains("install thing"));
        assert!(s.contains("model not installed"));
    }

    #[test]
    fn inference_display_includes_reason() {
        let e = DetectorError::Inference {
            detector: "test".into(),
            reason: "shape mismatch".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("inference failed"));
        assert!(s.contains("shape mismatch"));
    }

    #[test]
    fn io_display_includes_inner() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = DetectorError::Io {
            detector: "test".into(),
            source: io,
        };
        let s = format!("{e}");
        assert!(s.contains("io"));
        assert!(s.contains("missing"));
    }

    // ----- DetectorRegistry ----------

    #[test]
    fn registry_starts_empty() {
        let r = DetectorRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn registry_registers_detectors_in_order() {
        let mut r = DetectorRegistry::new();
        r.register(Box::new(AlwaysNegative {
            name: "first",
            families: vec![DetectionFamily::Audio],
            confidence: 0.1,
        }));
        r.register(Box::new(AlwaysNegative {
            name: "second",
            families: vec![DetectionFamily::Video],
            confidence: 0.2,
        }));
        assert_eq!(r.len(), 2);
        assert!(!r.is_empty());

        let results = r.run_all(&[]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].detector, "first");
        assert_eq!(results[1].detector, "second");
    }

    #[test]
    fn registry_run_all_collects_results_from_every_detector() {
        let mut r = DetectorRegistry::new();
        r.register(Box::new(AlwaysNegative {
            name: "neg",
            families: vec![DetectionFamily::Audio],
            confidence: 0.1,
        }));

        let results = r.run_all(b"any bytes");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, DetectionStatus::NotDetected);
        assert!(!results[0].detected);
        assert_eq!(results[0].confidence, 0.1);
    }

    #[test]
    fn registry_projects_detector_errors_onto_error_status() {
        // A detector that returns Err must surface as
        // DetectionResult { status: Error, ... } in the
        // dispatch output. The registry NEVER short-circuits.
        let mut r = DetectorRegistry::new();
        r.register(Box::new(AlwaysModelMissing { name: "missing" }));
        r.register(Box::new(AlwaysNegative {
            name: "neg",
            families: vec![DetectionFamily::Audio],
            confidence: 0.1,
        }));

        let results = r.run_all(b"any");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, DetectionStatus::Error);
        assert!(results[0].message.is_some());
        assert!(results[0].message.as_ref().unwrap().contains("model not installed"));
        // The second detector still runs.
        assert_eq!(results[1].status, DetectionStatus::NotDetected);
    }

    #[test]
    fn detector_trait_is_object_safe() {
        // The trait MUST be object-safe so Vec<Box<dyn Detector>>
        // compiles. Pin via a constructor that exercises the
        // boxed-dyn form.
        let _: Box<dyn Detector> = Box::new(AlwaysNegative {
            name: "test",
            families: vec![DetectionFamily::Audio],
            confidence: 0.0,
        });
    }

    #[test]
    fn detector_trait_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Detector>();
        assert_send_sync::<Box<dyn Detector>>();
        assert_send_sync::<DetectorRegistry>();
    }

    #[test]
    fn registry_debug_includes_detector_names() {
        let mut r = DetectorRegistry::new();
        r.register(Box::new(AlwaysNegative {
            name: "first-det",
            families: vec![DetectionFamily::Audio],
            confidence: 0.0,
        }));
        let s = format!("{r:?}");
        assert!(s.contains("first-det"));
        assert!(s.contains("len: 1"));
    }
}
