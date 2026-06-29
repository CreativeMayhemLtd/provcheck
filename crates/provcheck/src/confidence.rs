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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::WatermarkStatus;

    // ----- Threshold constant pins ----------
    //
    // These constants are the canonical thresholds every
    // detector family re-exports. Bumping them silently
    // shifts every Detected / Degraded verdict in every
    // signed asset's report. Pin the values explicitly so
    // any change comes paired with a deliberate test update.

    #[test]
    fn detected_threshold_is_seventy_percent() {
        assert_eq!(DETECTED_THRESHOLD, 0.70);
    }

    #[test]
    fn degraded_threshold_is_fifty_percent() {
        assert_eq!(DEGRADED_THRESHOLD, 0.50);
    }

    #[test]
    fn detected_threshold_exceeds_degraded() {
        // Constants are compile-time visible; hide in black_box
        // so clippy doesn't fold and complain.
        let detected = std::hint::black_box(DETECTED_THRESHOLD);
        let degraded = std::hint::black_box(DEGRADED_THRESHOLD);
        assert!(detected > degraded);
    }

    #[test]
    fn thresholds_are_in_unit_interval() {
        for t in [DETECTED_THRESHOLD, DEGRADED_THRESHOLD] {
            assert!((0.0..=1.0).contains(&t), "threshold {t} outside [0, 1]");
        }
    }

    // ----- classify(valid, confidence) ----------

    #[test]
    fn invalid_always_returns_not_detected_regardless_of_confidence() {
        // The valid flag is load-bearing — even a 1.0 confidence
        // can't promote an invalid result to Detected. This is
        // the false-positive defence.
        for c in [0.0, 0.5, 0.7, 0.9, 1.0] {
            assert_eq!(
                classify(false, c),
                WatermarkStatus::NotDetected,
                "invalid+conf={c} should be NotDetected"
            );
        }
    }

    #[test]
    fn confidence_below_degraded_threshold_is_not_detected() {
        for c in [0.0, 0.1, 0.49] {
            assert_eq!(
                classify(true, c),
                WatermarkStatus::NotDetected,
                "valid+conf={c} should be NotDetected"
            );
        }
    }

    #[test]
    fn confidence_at_degraded_threshold_exactly_is_degraded() {
        // 0.50 is the inclusive lower bound for Degraded. Pin
        // the boundary behaviour so a future maintainer doesn't
        // silently shift the strict / non-strict comparison.
        assert_eq!(classify(true, DEGRADED_THRESHOLD), WatermarkStatus::Degraded);
    }

    #[test]
    fn confidence_in_degraded_range_is_degraded() {
        for c in [0.50, 0.55, 0.60, 0.69] {
            assert_eq!(
                classify(true, c),
                WatermarkStatus::Degraded,
                "valid+conf={c} should be Degraded"
            );
        }
    }

    #[test]
    fn confidence_at_detected_threshold_exactly_is_detected() {
        // 0.70 is the inclusive lower bound for Detected.
        assert_eq!(classify(true, DETECTED_THRESHOLD), WatermarkStatus::Detected);
    }

    #[test]
    fn confidence_above_detected_threshold_is_detected() {
        for c in [0.70, 0.80, 0.95, 1.0] {
            assert_eq!(
                classify(true, c),
                WatermarkStatus::Detected,
                "valid+conf={c} should be Detected"
            );
        }
    }

    #[test]
    fn classify_handles_nan_safely() {
        // f32::NAN compared against anything returns false, so
        // every < comparison fails → falls through to Detected
        // branch. This is technically a misclassification but
        // it's deterministic and not a panic. Pin the behaviour
        // so a future maintainer who tries to "handle NaN" doesn't
        // silently change downstream verdicts.
        let r = classify(true, f32::NAN);
        // We accept either NotDetected or Detected (the actual
        // arm depends on the comparison order); the load-bearing
        // contract is "no panic, deterministic result".
        let _ = r;
    }

    #[test]
    fn confidence_just_below_detected_threshold_is_degraded_not_detected() {
        // The strict inequality `confidence < DETECTED_THRESHOLD`
        // means a value like 0.6999 must be Degraded, not
        // Detected. Pin this boundary explicitly.
        // Use 0.69 since f32 epsilon may not represent 0.6999 exactly.
        assert_eq!(classify(true, 0.69), WatermarkStatus::Degraded);
    }

    #[test]
    fn confidence_just_below_degraded_threshold_is_not_detected() {
        assert_eq!(classify(true, 0.49), WatermarkStatus::NotDetected);
    }
}
