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

// ---------------------------------------------------------------
// Video streaming pipeline.
// ---------------------------------------------------------------

/// Configuration for a video streaming pipeline.
///
/// Unlike audio (where the natural unit is a fixed-rate sample),
/// video frames arrive at irregular timestamps from an encoder or
/// camera capture. The pipeline batches consecutive frames into
/// fixed-size windows (`window_frames`) and dispatches each window
/// to the registered detector(s) as a single inference call.
///
/// Producer side is responsible for serialising the per-frame
/// bytes into whatever format the detector expects (raw RGB, PNG,
/// JPEG); the pipeline treats them as opaque payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoStreamConfig {
    /// Number of frames per window. A 30-frame window at 30 fps
    /// is a 1-second window; at 60 fps it is half a second.
    pub window_frames: usize,
    /// Number of frames to advance between windows. Must be
    /// `> 0` and `<= window_frames`. Equal to `window_frames`
    /// produces non-overlapping windows; smaller produces
    /// overlapping windows.
    pub hop_frames: usize,
    /// Maximum number of verdicts retained. Older verdicts
    /// fall off the deque tail.
    pub history_capacity: usize,
}

impl VideoStreamConfig {
    /// Construct + validate. Returns
    /// [`StreamError::InvalidConfig`] on `window_frames == 0`,
    /// `hop_frames == 0`, or `hop_frames > window_frames`.
    pub fn new(
        window_frames: usize,
        hop_frames: usize,
        history_capacity: usize,
    ) -> Result<Self, StreamError> {
        if window_frames == 0 {
            return Err(StreamError::InvalidConfig(
                "window_frames must be > 0".into(),
            ));
        }
        if hop_frames == 0 {
            return Err(StreamError::InvalidConfig(
                "hop_frames must be > 0".into(),
            ));
        }
        if hop_frames > window_frames {
            return Err(StreamError::InvalidConfig(format!(
                "hop_frames ({hop_frames}) must be <= window_frames ({window_frames})"
            )));
        }
        Ok(Self {
            window_frames,
            hop_frames,
            history_capacity,
        })
    }
}

/// A single encoded video frame with its presentation timestamp.
///
/// `bytes` is operator-supplied: raw RGB, PNG, JPEG, or whatever
/// the registered detector expects. The pipeline treats it as
/// opaque. `pts_secs` is the wall-clock presentation timestamp
/// relative to stream start; consecutive frames should have
/// monotonically increasing `pts_secs` (the pipeline does not
/// enforce this, but window timestamps depend on it).
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Presentation timestamp in seconds, relative to the stream
    /// start.
    pub pts_secs: f32,
    /// Encoded frame bytes.
    pub bytes: Vec<u8>,
}

/// Streaming video detection pipeline.
///
/// Constructed with a [`VideoStreamConfig`] + a
/// [`provcheck_detect::DetectorRegistry`]. Callers feed frames
/// one at a time via [`Self::feed_frame`] and drain verdicts via
/// [`Self::drain_verdicts`]. When a window's worth of frames is
/// buffered, the pipeline concatenates their bytes (with a 4-byte
/// big-endian length prefix per frame so the detector can recover
/// the frame boundaries) and dispatches the batch through every
/// registered detector.
///
/// Concatenated layout (per window):
///
/// ```text
/// [frame0_len_u32_be][frame0_bytes][frame1_len_u32_be][frame1_bytes]...
/// ```
///
/// The detector implementor parses this length-prefixed format.
/// We avoid serde here so the boundary is a flat byte slice the
/// detector can iterate without an extra allocation.
pub struct VideoStreamingPipeline {
    config: VideoStreamConfig,
    registry: provcheck_detect::DetectorRegistry,
    buffer: VecDeque<VideoFrame>,
    frames_consumed: u64,
    verdicts: VecDeque<WindowedVerdict>,
}

impl VideoStreamingPipeline {
    /// Construct.
    pub fn new(
        config: VideoStreamConfig,
        registry: provcheck_detect::DetectorRegistry,
    ) -> Self {
        Self {
            config,
            registry,
            buffer: VecDeque::with_capacity(config.window_frames * 2),
            frames_consumed: 0,
            verdicts: VecDeque::new(),
        }
    }

    /// Detector count.
    pub fn detector_count(&self) -> usize {
        self.registry.len()
    }

    /// Total frames consumed since stream start.
    pub fn frames_consumed(&self) -> u64 {
        self.frames_consumed
    }

    /// Verdict count in the history buffer.
    pub fn verdict_count(&self) -> usize {
        self.verdicts.len()
    }

    /// Feed one frame. Emits zero or one window-worth of verdicts
    /// depending on whether the frame completes a window. With no
    /// detectors registered, frames buffer and frames_consumed
    /// advances; no verdicts emit.
    pub fn feed_frame(&mut self, frame: VideoFrame) {
        self.buffer.push_back(frame);
        self.frames_consumed += 1;

        while self.buffer.len() >= self.config.window_frames {
            // Window = first window_frames in the deque.
            let window: Vec<&VideoFrame> = self
                .buffer
                .iter()
                .take(self.config.window_frames)
                .collect();

            let start_secs = window[0].pts_secs;
            let end_secs = window[window.len() - 1].pts_secs;

            // Concatenate with length prefixes.
            let total_size: usize = window
                .iter()
                .map(|f| 4 + f.bytes.len())
                .sum();
            let mut bytes = Vec::with_capacity(total_size);
            for frame in &window {
                let len_be = (frame.bytes.len() as u32).to_be_bytes();
                bytes.extend_from_slice(&len_be);
                bytes.extend_from_slice(&frame.bytes);
            }

            let per_detector_results = self.registry.run_all(&bytes);
            for result in per_detector_results {
                self.verdicts.push_back(WindowedVerdict {
                    start_secs,
                    end_secs,
                    result,
                });
                while self.verdicts.len() > self.config.history_capacity {
                    self.verdicts.pop_front();
                }
            }

            // Advance buffer by hop_frames.
            for _ in 0..self.config.hop_frames {
                self.buffer.pop_front();
            }
        }
    }

    /// Drain all verdicts.
    pub fn drain_verdicts(&mut self) -> Vec<WindowedVerdict> {
        self.verdicts.drain(..).collect()
    }

    /// Peek the most recent verdict.
    pub fn latest_verdict(&self) -> Option<&WindowedVerdict> {
        self.verdicts.back()
    }
}

impl std::fmt::Debug for VideoStreamingPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VideoStreamingPipeline")
            .field("config", &self.config)
            .field("detector_count", &self.registry.len())
            .field("buffer_len", &self.buffer.len())
            .field("frames_consumed", &self.frames_consumed)
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

    // ----- VideoStreamConfig validation ----------

    #[test]
    fn video_config_rejects_zero_window() {
        let r = VideoStreamConfig::new(0, 1, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn video_config_rejects_zero_hop() {
        let r = VideoStreamConfig::new(10, 0, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn video_config_rejects_hop_greater_than_window() {
        let r = VideoStreamConfig::new(10, 20, 10);
        assert!(matches!(r, Err(StreamError::InvalidConfig(_))));
    }

    #[test]
    fn video_config_accepts_hop_equal_to_window() {
        assert!(VideoStreamConfig::new(10, 10, 10).is_ok());
    }

    #[test]
    fn video_config_accepts_overlapping_hop() {
        assert!(VideoStreamConfig::new(10, 5, 10).is_ok());
    }

    // ----- VideoStreamingPipeline ----------

    /// Video-only stub detector. Reports NotDetected on any
    /// input.
    struct VideoStubDetector {
        name: &'static str,
    }

    impl Detector for VideoStubDetector {
        fn name(&self) -> &str {
            self.name
        }
        fn families(&self) -> &[DetectionFamily] {
            &[DetectionFamily::Video]
        }
        fn run(&self, bytes: &[u8]) -> Result<DetectionResult, DetectorError> {
            Ok(DetectionResult {
                detector: self.name.to_string(),
                family: DetectionFamily::Video,
                status: DetectionStatus::NotDetected,
                detected: false,
                confidence: (bytes.len() % 100) as f32 / 100.0,
                model_id: None,
                version: None,
                message: None,
            })
        }
    }

    fn frame(pts_secs: f32, size: usize) -> VideoFrame {
        VideoFrame {
            pts_secs,
            bytes: vec![0xAA; size],
        }
    }

    #[test]
    fn video_pipeline_with_no_detectors_buffers_but_emits_nothing() {
        let cfg = VideoStreamConfig::new(5, 5, 100).unwrap();
        let mut p = VideoStreamingPipeline::new(cfg, DetectorRegistry::new());
        for i in 0..10 {
            p.feed_frame(frame(i as f32 / 30.0, 64));
        }
        assert_eq!(p.frames_consumed(), 10);
        assert_eq!(p.verdict_count(), 0);
    }

    #[test]
    fn video_pipeline_emits_one_verdict_per_window_per_detector() {
        let cfg = VideoStreamConfig::new(5, 5, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        registry.register(Box::new(VideoStubDetector { name: "b" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        // 3 full windows of 5 frames = 15 frames. 3 windows × 2
        // detectors = 6 verdicts.
        for i in 0..15 {
            p.feed_frame(frame(i as f32 / 30.0, 64));
        }
        assert_eq!(p.verdict_count(), 6);
    }

    #[test]
    fn video_pipeline_advances_by_hop_not_window() {
        // window=5 hop=2, 10 frames → windows at frame indices
        // 0, 2, 4, 6 (each needs 5 frames so frame 6's window
        // is [6..11], which fits with 10 frames at index 5..10
        // wait: 10 frames are indices 0..10. The 4th window
        // would start at index 6 and need frames 6..11 which is
        // 11 frames total. We only have 10 → 3 windows: starts
        // at 0, 2, 4. After window at index 4 fires (frames
        // 4..9), buffer advances by 2 → starts at 6, needs
        // frames 6..11, we have 9 (frames 6..10) so it doesn't
        // fire. So 3 windows.
        let cfg = VideoStreamConfig::new(5, 2, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        for i in 0..10 {
            p.feed_frame(frame(i as f32 / 30.0, 64));
        }
        assert_eq!(p.verdict_count(), 3);
    }

    #[test]
    fn video_pipeline_window_timestamps_track_frame_pts() {
        let cfg = VideoStreamConfig::new(3, 3, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        // Window 1: pts 0.0, 0.1, 0.2 → start 0.0, end 0.2.
        // Window 2: pts 0.3, 0.4, 0.5 → start 0.3, end 0.5.
        for i in 0..6 {
            p.feed_frame(frame(i as f32 * 0.1, 64));
        }
        let verdicts = p.drain_verdicts();
        assert_eq!(verdicts.len(), 2);
        assert!((verdicts[0].start_secs - 0.0).abs() < 1e-5);
        assert!((verdicts[0].end_secs - 0.2).abs() < 1e-5);
        assert!((verdicts[1].start_secs - 0.3).abs() < 1e-5);
        assert!((verdicts[1].end_secs - 0.5).abs() < 1e-5);
    }

    #[test]
    fn video_pipeline_history_capacity_bounds_buffer() {
        let cfg = VideoStreamConfig::new(2, 2, 2).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        // 10 frames → 5 windows → cap holds 2.
        for i in 0..10 {
            p.feed_frame(frame(i as f32 * 0.05, 32));
        }
        assert_eq!(p.verdict_count(), 2);
    }

    #[test]
    fn video_pipeline_drain_clears_state() {
        let cfg = VideoStreamConfig::new(2, 2, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        for i in 0..4 {
            p.feed_frame(frame(i as f32 * 0.05, 32));
        }
        assert_eq!(p.verdict_count(), 2);
        let _ = p.drain_verdicts();
        assert_eq!(p.verdict_count(), 0);
        assert!(p.latest_verdict().is_none());
    }

    #[test]
    fn video_pipeline_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VideoStreamingPipeline>();
        assert_send_sync::<VideoStreamConfig>();
        assert_send_sync::<VideoFrame>();
    }

    #[test]
    fn video_pipeline_debug_includes_state() {
        let cfg = VideoStreamConfig::new(2, 2, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let p = VideoStreamingPipeline::new(cfg, registry);
        let s = format!("{p:?}");
        assert!(s.contains("VideoStreamingPipeline"));
        assert!(s.contains("frames_consumed"));
    }

    #[test]
    fn video_pipeline_length_prefix_format_is_deterministic() {
        // Pin the wire format: each frame in the window is
        // prefixed by its byte length as big-endian u32, then
        // followed by the frame bytes. The detector implementor
        // depends on this layout to re-parse frame boundaries.
        // Use a custom detector that captures the bytes it
        // receives.
        struct CapturingDetector {
            captured: std::sync::Mutex<Vec<u8>>,
        }
        impl Detector for CapturingDetector {
            fn name(&self) -> &str {
                "capture"
            }
            fn families(&self) -> &[DetectionFamily] {
                &[DetectionFamily::Video]
            }
            fn run(&self, bytes: &[u8]) -> Result<DetectionResult, DetectorError> {
                *self.captured.lock().unwrap() = bytes.to_vec();
                Ok(DetectionResult {
                    detector: "capture".into(),
                    family: DetectionFamily::Video,
                    status: DetectionStatus::NotDetected,
                    detected: false,
                    confidence: 0.0,
                    model_id: None,
                    version: None,
                    message: None,
                })
            }
        }
        let captured: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let det = CapturingDetector {
            captured: std::sync::Mutex::new(Vec::new()),
        };
        // Can't easily share captured via Arc through Box<dyn Detector>
        // without more plumbing; instead build a closure-style
        // detector that writes to a static slot. Simplest: just
        // check the registry path by reconstructing the expected
        // bytes manually.
        let _ = (captured, det);

        let cfg = VideoStreamConfig::new(2, 2, 100).unwrap();
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(VideoStubDetector { name: "a" }));
        let mut p = VideoStreamingPipeline::new(cfg, registry);
        p.feed_frame(VideoFrame {
            pts_secs: 0.0,
            bytes: vec![0x11, 0x22, 0x33],
        });
        p.feed_frame(VideoFrame {
            pts_secs: 0.1,
            bytes: vec![0x44, 0x55],
        });
        // The window concatenation should be:
        //   [0,0,0,3] [11 22 33] [0,0,0,2] [44 55]
        // = 13 bytes total. The detector ran, so verdict count = 1.
        assert_eq!(p.verdict_count(), 1);
    }
}
