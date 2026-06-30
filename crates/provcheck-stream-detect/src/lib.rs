//! Streaming intake pipeline for AI-content detection.
//!
//! The companion to [`provcheck_detect`]: provides chunked /
//! rolling-window detection for live streams (microphone, screen
//! capture, RTSP feeds, frame batches from a video encoder) where
//! the verifier-style one-shot bytes-in / verdict-out shape doesn't
//! match the data flow.
//!
//! This crate ships **only the intake plumbing**. The classifier
//! itself is bring-your-own via [`provcheck_detect::Detector`]:
//! either a commercial paid-DLC pack (Creative Mayhem-distributed
//! after v1.0; first such pack is sourced from the doomscroll.fm
//! pipeline and is NOT in this open repo at any version) or an
//! operator-supplied open-source third-party detector wrapped via
//! the public trait.
//!
//! See `docs/v0.9-roadmap/README.md` section 9b for the design
//! rationale.
//!
//! ## Streams covered
//!
//! - **Audio PCM chunks**: feed `f32` mono PCM samples at a known
//!   sample rate. The pipeline buffers samples into windows of
//!   configurable size, advances by configurable hop, and dispatches
//!   each window through the registered detector(s).
//! - **Video frame batches**: feed sequences of encoded frame bytes
//!   (PNG / JPEG / raw RGB) with their per-frame timestamps. The
//!   pipeline batches consecutive frames into a window and dispatches
//!   the batch as a single inference call.
//!
//! ## Rolling-window contract
//!
//! Window size and hop are operator-supplied. The pipeline NEVER
//! looks ahead beyond what's been fed — a window emits when the
//! buffer has accumulated `window_size` units of input, then the
//! buffer advances by `hop` units and the next window emits when
//! the buffer is full again. No backfill, no padding, no future-
//! frame peeking.
//!
//! Per-window detection results land in a deque keyed by the
//! window's start timestamp. Callers can:
//!
//! - Drain the deque (consume all available verdicts).
//! - Peek the most recent verdict (the "live" detection state).
//! - Aggregate over a recent time range (average / max / vote).
//!
//! ## Pipeline state
//!
//! The pipeline is owned by one thread (the intake thread). To
//! receive verdicts in another thread (e.g. an async event loop
//! that ships them onward), the caller wires an mpsc channel and
//! drains in the consumer thread.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;

use provcheck_detect::DetectionResult;
use serde::{Deserialize, Serialize};

/// Configuration for an audio streaming pipeline.
///
/// `sample_rate` and `window_samples` / `hop_samples` together
/// determine the window's wall-clock duration. The detector is
/// responsible for handling whatever sample rate the pipeline
/// produces — adapter / resampling is out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioStreamConfig {
    /// PCM sample rate the pipeline expects (Hz). Producer side is
    /// responsible for delivering samples at this rate.
    pub sample_rate: u32,
    /// Number of samples per window. A 1-second window at 16 kHz
    /// is 16_000; at 44.1 kHz it is 44_100.
    pub window_samples: usize,
    /// Number of samples to advance between windows. `window_samples`
    /// produces non-overlapping windows; smaller values produce
    /// overlapping windows. Must be `> 0` and `<= window_samples`.
    pub hop_samples: usize,
    /// Maximum number of recent verdicts to retain. Older verdicts
    /// fall off the deque tail. `usize::MAX` for unbounded retention
    /// (memory-unsafe on long-running streams; pick a real value).
    pub history_capacity: usize,
}

impl AudioStreamConfig {
    /// Construct a config and validate the invariants. Returns
    /// [`StreamError::InvalidConfig`] if any of `window_samples == 0`,
    /// `hop_samples == 0`, `hop_samples > window_samples`, or
    /// `sample_rate == 0`.
    pub fn new(
        sample_rate: u32,
        window_samples: usize,
        hop_samples: usize,
        history_capacity: usize,
    ) -> Result<Self, StreamError> {
        if sample_rate == 0 {
            return Err(StreamError::InvalidConfig(
                "sample_rate must be > 0".into(),
            ));
        }
        if window_samples == 0 {
            return Err(StreamError::InvalidConfig(
                "window_samples must be > 0".into(),
            ));
        }
        if hop_samples == 0 {
            return Err(StreamError::InvalidConfig(
                "hop_samples must be > 0".into(),
            ));
        }
        if hop_samples > window_samples {
            return Err(StreamError::InvalidConfig(format!(
                "hop_samples ({hop_samples}) must be <= window_samples ({window_samples})"
            )));
        }
        Ok(Self {
            sample_rate,
            window_samples,
            hop_samples,
            history_capacity,
        })
    }

    /// Wall-clock duration of one window, in seconds.
    pub fn window_duration_secs(&self) -> f32 {
        self.window_samples as f32 / self.sample_rate as f32
    }

    /// Wall-clock spacing between consecutive windows, in seconds.
    pub fn hop_duration_secs(&self) -> f32 {
        self.hop_samples as f32 / self.sample_rate as f32
    }
}

/// A timestamped verdict from the streaming pipeline. Wraps a
/// [`DetectionResult`] with the window's start timestamp (in
/// seconds, relative to stream start) so consumers can plot
/// confidence over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowedVerdict {
    /// Start time of the window that produced this verdict
    /// (seconds, relative to the stream's first sample).
    pub start_secs: f32,
    /// End time of the window (start + window_duration).
    pub end_secs: f32,
    /// The detector's per-window result.
    pub result: DetectionResult,
}

/// Streaming-pipeline error.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Configuration failed validation (zero rate, hop > window,
    /// etc.). Carries an operator-facing reason.
    #[error("invalid stream config: {0}")]
    InvalidConfig(String),

    /// A detector returned an error during `run`. The intake
    /// continues — the pipeline projects the detector error onto a
    /// per-window verdict with `status = Error` and emits it. This
    /// variant is only used when no detector is registered AND
    /// the caller invokes a method that requires one.
    #[error("no detectors registered in the pipeline")]
    NoDetectorRegistered,
}

/// Streaming audio detection pipeline.
///
/// Constructed with an [`AudioStreamConfig`] + a
/// [`provcheck_detect::DetectorRegistry`] (passed by ownership).
/// Callers feed `f32` PCM samples via [`Self::feed`] and drain
/// verdicts via [`Self::drain_verdicts`].
///
/// The pipeline is **not thread-safe by itself** — wrap in a
/// `Mutex` if multiple threads feed it. The detector trait is
/// `Send + Sync` so the registry can move across threads with the
/// pipeline.
pub struct AudioStreamingPipeline {
    config: AudioStreamConfig,
    registry: provcheck_detect::DetectorRegistry,
    buffer: VecDeque<f32>,
    samples_consumed: u64,
    verdicts: VecDeque<WindowedVerdict>,
}

impl AudioStreamingPipeline {
    /// Construct a new pipeline.
    pub fn new(
        config: AudioStreamConfig,
        registry: provcheck_detect::DetectorRegistry,
    ) -> Self {
        Self {
            config,
            registry,
            buffer: VecDeque::with_capacity(config.window_samples * 2),
            samples_consumed: 0,
            verdicts: VecDeque::new(),
        }
    }

    /// Number of detectors registered. Convenience pass-through.
    pub fn detector_count(&self) -> usize {
        self.registry.len()
    }

    /// Number of verdicts currently in the history buffer.
    pub fn verdict_count(&self) -> usize {
        self.verdicts.len()
    }

    /// Total samples consumed since the stream began. Useful for
    /// debugging "is the stream actually flowing?" questions.
    pub fn samples_consumed(&self) -> u64 {
        self.samples_consumed
    }

    /// Feed PCM samples into the pipeline. Emits zero or more
    /// per-window verdicts depending on how full the buffer was
    /// before the call. Verdicts land in the internal history
    /// deque; drain via [`Self::drain_verdicts`].
    ///
    /// With no detectors registered, the feed still buffers
    /// samples and advances state — no verdicts emit. Useful for
    /// the operator-pattern where the stream might start before
    /// the operator registers a detector.
    pub fn feed(&mut self, samples: &[f32]) {
        self.buffer.extend(samples.iter().copied());
        self.samples_consumed += samples.len() as u64;

        // Emit as many windows as we have data for.
        while self.buffer.len() >= self.config.window_samples {
            // Materialise the window slice (VecDeque can be split;
            // we take a contiguous Vec for the detector trait).
            let window: Vec<f32> = self
                .buffer
                .iter()
                .copied()
                .take(self.config.window_samples)
                .collect();

            // Compute the window's wall-clock bounds.
            // samples_consumed is total samples consumed; the
            // window started `buffer.len()` samples ago.
            let window_start_sample = self.samples_consumed - self.buffer.len() as u64;
            let start_secs = window_start_sample as f32 / self.config.sample_rate as f32;
            let end_secs = start_secs + self.config.window_duration_secs();

            // Detector trait operates on bytes; serialise the
            // f32 PCM window into little-endian bytes for the
            // detector. The implementor is responsible for
            // interpreting them (PCM f32 LE at sample_rate Hz).
            // We avoid an unsafe transmute so the crate can keep
            // `#![forbid(unsafe_code)]` — at ~64 KB per window
            // the per-iteration alloc is in the noise.
            let mut bytes = Vec::with_capacity(window.len() * 4);
            for s in &window {
                bytes.extend_from_slice(&s.to_le_bytes());
            }
            let per_detector_results = self.registry.run_all(&bytes);
            for result in per_detector_results {
                self.verdicts.push_back(WindowedVerdict {
                    start_secs,
                    end_secs,
                    result,
                });
                // Bound the history.
                while self.verdicts.len() > self.config.history_capacity {
                    self.verdicts.pop_front();
                }
            }

            // Advance buffer by hop_samples.
            for _ in 0..self.config.hop_samples {
                self.buffer.pop_front();
            }
        }
    }

    /// Drain all currently-buffered verdicts and clear the
    /// internal history. Returns them in emission order
    /// (chronological by `start_secs`).
    pub fn drain_verdicts(&mut self) -> Vec<WindowedVerdict> {
        self.verdicts.drain(..).collect()
    }

    /// Peek the most recent verdict without consuming the
    /// history. Returns `None` if no verdicts have been emitted
    /// yet (no detector registered, or not enough samples fed).
    pub fn latest_verdict(&self) -> Option<&WindowedVerdict> {
        self.verdicts.back()
    }
}

impl std::fmt::Debug for AudioStreamingPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioStreamingPipeline")
            .field("config", &self.config)
            .field("detector_count", &self.registry.len())
            .field("buffer_len", &self.buffer.len())
            .field("samples_consumed", &self.samples_consumed)
            .field("verdict_count", &self.verdicts.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provcheck_detect::{
        DetectionFamily, DetectionResult, DetectionStatus, Detector,
        DetectorError, DetectorRegistry,
    };

    /// Test detector that always reports NotDetected. We don't
    /// need to count calls — the `verdict_count` on the pipeline
    /// already tells us how many times the detector fired.
    struct StubDetector {
        name: &'static str,
    }

    impl StubDetector {
        fn new(name: &'static str) -> Self {
            Self { name }
        }
    }

    impl Detector for StubDetector {
        fn name(&self) -> &str {
            self.name
        }
        fn families(&self) -> &[DetectionFamily] {
            &[DetectionFamily::Audio]
        }
        fn run(&self, bytes: &[u8]) -> Result<DetectionResult, DetectorError> {
            Ok(DetectionResult {
                detector: self.name.to_string(),
                family: DetectionFamily::Audio,
                status: DetectionStatus::NotDetected,
                detected: false,
                // Confidence varies with byte count so tests can
                // distinguish windows.
                confidence: (bytes.len() % 100) as f32 / 100.0,
                model_id: None,
                version: None,
                message: None,
            })
        }
    }

    // ----- AudioStreamConfig validation ----------

    #[test]
    fn config_rejects_zero_sample_rate() {
        let r = AudioStreamConfig::new(0, 100, 50, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn config_rejects_zero_window() {
        let r = AudioStreamConfig::new(16000, 0, 1, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn config_rejects_zero_hop() {
        let r = AudioStreamConfig::new(16000, 100, 0, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn config_rejects_hop_greater_than_window() {
        let r = AudioStreamConfig::new(16000, 100, 200, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn config_accepts_hop_equal_to_window() {
        // Non-overlapping windows.
        let r = AudioStreamConfig::new(16000, 100, 100, 10);
        assert!(r.is_ok());
    }

    #[test]
    fn config_accepts_overlapping_hop() {
        // 50% overlap.
        let r = AudioStreamConfig::new(16000, 100, 50, 10);
        assert!(r.is_ok());
    }

    #[test]
    fn config_window_duration_at_16khz() {
        let c = AudioStreamConfig::new(16000, 16000, 16000, 10).unwrap();
        assert!((c.window_duration_secs() - 1.0).abs() < 1e-6);
    }

    // ----- AudioStreamingPipeline ----------

    #[test]
    fn pipeline_with_no_detectors_buffers_but_emits_nothing() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let registry = DetectorRegistry::new();
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.0_f32; 5000]);
        assert_eq!(p.samples_consumed(), 5000);
        assert_eq!(p.verdict_count(), 0);
        assert_eq!(p.detector_count(), 0);
    }

    #[test]
    fn pipeline_emits_one_verdict_per_window_per_detector() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        registry.register(Box::new(StubDetector::new("b")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        // 3 full windows of input (3000 samples at non-overlapping
        // hop). Expect 3 windows × 2 detectors = 6 verdicts.
        p.feed(&vec![0.1_f32; 3000]);
        assert_eq!(p.verdict_count(), 6);
    }

    #[test]
    fn pipeline_advances_buffer_by_hop_not_window() {
        // With window=100, hop=50, feeding 250 samples should
        // produce 4 windows (starting at samples 0, 50, 100,
        // 150). Sample 200's window would need 100 more samples
        // we don't have.
        let cfg = AudioStreamConfig::new(16000, 100, 50, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 250]);
        // Windows starting at: 0, 50, 100, 150 → 4 windows.
        assert_eq!(p.verdict_count(), 4);
    }

    #[test]
    fn pipeline_records_chronological_start_times() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 3000]);
        let verdicts = p.drain_verdicts();
        assert_eq!(verdicts.len(), 3);
        // start_secs should be monotonically increasing.
        for w in verdicts.windows(2) {
            assert!(
                w[1].start_secs > w[0].start_secs,
                "non-monotonic window start times"
            );
        }
    }

    #[test]
    fn pipeline_window_timestamps_match_sample_positions() {
        // window=1000 samples at 16 kHz = 0.0625 seconds.
        // First window: starts at sample 0 → start_secs = 0.
        // Second window: starts at sample 1000 → start_secs =
        // 1000 / 16000 = 0.0625.
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 2000]);
        let verdicts = p.drain_verdicts();
        assert_eq!(verdicts.len(), 2);
        assert!((verdicts[0].start_secs - 0.0).abs() < 1e-6);
        assert!((verdicts[1].start_secs - 0.0625).abs() < 1e-6);
        // End of first window should equal start of second
        // (non-overlapping).
        assert!((verdicts[0].end_secs - verdicts[1].start_secs).abs() < 1e-6);
    }

    #[test]
    fn pipeline_history_capacity_bounds_verdict_buffer() {
        // Capacity = 2, feed enough for 5 verdicts.
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 2).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 5000]);
        // Capacity caps the buffer at 2.
        assert_eq!(p.verdict_count(), 2);
        let verdicts = p.drain_verdicts();
        // The retained verdicts should be the LATEST two (FIFO
        // eviction). start_secs of the last verdict should be
        // 4 * window_duration = 4 * 0.0625 = 0.25.
        assert!(
            (verdicts[1].start_secs - 0.25).abs() < 1e-6,
            "retained verdict 1 should be the last emitted (start_secs=0.25), got {}",
            verdicts[1].start_secs
        );
    }

    #[test]
    fn pipeline_drain_clears_history() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 3000]);
        let _ = p.drain_verdicts();
        assert_eq!(p.verdict_count(), 0);
        assert!(p.latest_verdict().is_none());
    }

    #[test]
    fn pipeline_latest_verdict_returns_most_recent() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 3000]);
        let latest = p.latest_verdict().expect("expected a verdict");
        // Most recent window starts at sample 2000 (third window).
        assert!((latest.start_secs - (2000.0 / 16000.0)).abs() < 1e-6);
    }

    #[test]
    fn pipeline_overlapping_windows_emit_independent_verdicts() {
        // window=100, hop=50 → 50% overlap.
        let cfg = AudioStreamConfig::new(16000, 100, 50, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let mut p = AudioStreamingPipeline::new(cfg, registry);

        p.feed(&vec![0.1_f32; 200]);
        // Windows: [0..100], [50..150], [100..200] → 3 windows.
        assert_eq!(p.verdict_count(), 3);
    }

    #[test]
    fn pipeline_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AudioStreamingPipeline>();
        assert_send_sync::<AudioStreamConfig>();
        assert_send_sync::<WindowedVerdict>();
    }

    #[test]
    fn pipeline_debug_includes_state() {
        let cfg = AudioStreamConfig::new(16000, 1000, 1000, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(StubDetector::new("a")));
        let p = AudioStreamingPipeline::new(cfg, registry);
        let s = format!("{p:?}");
        assert!(s.contains("AudioStreamingPipeline"));
        assert!(s.contains("detector_count"));
    }

    #[test]
    fn windowed_verdict_round_trips_through_serde() {
        let v = WindowedVerdict {
            start_secs: 1.5,
            end_secs: 2.5,
            result: DetectionResult {
                detector: "test".into(),
                family: DetectionFamily::Audio,
                status: DetectionStatus::Detected,
                detected: true,
                confidence: 0.9,
                model_id: Some("m1".into()),
                version: Some("1".into()),
                message: None,
            },
        };
        let json = serde_json::to_string(&v).expect("ser");
        let back: WindowedVerdict = serde_json::from_str(&json).expect("de");
        assert_eq!(back.start_secs, v.start_secs);
        assert_eq!(back.end_secs, v.end_secs);
        assert_eq!(back.result.detector, v.result.detector);
    }
}
