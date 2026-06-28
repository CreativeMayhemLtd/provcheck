//! Confidence thresholds for watermark + classifier reporting.
//!
//! These are report-level semantics shared across every watermark
//! family and (in v0.9+) the AI-classifier sibling, so they live in
//! `provcheck` rather than in any single family crate.
//!
//! v0.7 phase 7-pre audit #4. Previously these constants lived in
//! `provcheck-watermark::hparams` only; `provcheck-audioseal` and
//! `provcheck-wavmark` each had to re-derive the same thresholds.
//! Promoted here so each family crate can re-export the canonical
//! values without re-deriving them.
//!
//! Thresholds:
//!
//! - **`DETECTED_THRESHOLD = 0.70`** — confidence at or above this
//!   maps to [`WatermarkStatus::Detected`]. The mark is present and
//!   the report should treat it as load-bearing for downstream
//!   provenance claims.
//!
//! - **`DEGRADED_THRESHOLD = 0.50`** — confidence in
//!   `[0.50, 0.70)` maps to [`WatermarkStatus::Degraded`]. The mark
//!   is detected but margin is thin; downstream consumers should
//!   surface the conf number and not over-promise the verification.
//!
//! - Below `DEGRADED_THRESHOLD` maps to
//!   [`WatermarkStatus::NotDetected`].
//!
//! [`WatermarkStatus`]: crate::report::WatermarkStatus
//! [`WatermarkStatus::Detected`]: crate::report::WatermarkStatus::Detected
//! [`WatermarkStatus::Degraded`]: crate::report::WatermarkStatus::Degraded
//! [`WatermarkStatus::NotDetected`]: crate::report::WatermarkStatus::NotDetected

/// Confidence at or above this maps to `WatermarkStatus::Detected`.
pub const DETECTED_THRESHOLD: f32 = 0.70;

/// Confidence in `[DEGRADED_THRESHOLD, DETECTED_THRESHOLD)` maps to
/// `WatermarkStatus::Degraded`. Below this maps to `NotDetected`.
pub const DEGRADED_THRESHOLD: f32 = 0.50;

/// Convenience: classify a (valid, confidence) pair into the
/// canonical [`WatermarkStatus`]. Mirrors the per-crate `classify`
/// functions previously inlined in each family.
///
/// [`WatermarkStatus`]: crate::report::WatermarkStatus
pub fn classify(valid: bool, confidence: f32) -> crate::report::WatermarkStatus {
    use crate::report::WatermarkStatus;
    if !valid || confidence < DEGRADED_THRESHOLD {
        WatermarkStatus::NotDetected
    } else if confidence < DETECTED_THRESHOLD {
        WatermarkStatus::Degraded
    } else {
        WatermarkStatus::Detected
    }
}
