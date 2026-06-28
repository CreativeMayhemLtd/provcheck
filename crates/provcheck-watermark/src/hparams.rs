//! Detector configuration constants.
//!
//! These are the values from `models/hparams.json` lifted into
//! compile-time constants so we don't parse JSON at every
//! detection call. The JSON file is documentation; this module
//! is the source of truth for the running code.
//!
//! If the JSON file's values diverge from these constants, the
//! constants win — fix the JSON.

/// Sample rate the trained model expects. The encoder + decoder
/// were trained at this rate; resample mismatched audio to it
/// before STFT.
pub const SAMPLE_RATE: u32 = 44_100;

/// STFT FFT length. Defines the frequency-bin count
/// (= `N_FFT / 2 + 1` = 2049) and the analysis window size.
pub const N_FFT: usize = 4096;

/// Hop between STFT frames in samples. Two adjacent frames
/// share `N_FFT - HOP` = 2048 samples (50% overlap).
pub const HOP: usize = 2048;

/// Hann window length. Equal to `N_FFT` for this model.
pub const WIN: usize = 4096;

/// Number of STFT magnitude bins per frame. Equal to
/// `N_FFT / 2 + 1` for the one-sided (real) FFT.
pub const FREQ_BINS: usize = 2049;

/// Mean square energy of the VCTK speech corpus the model was
/// normalised to during training. Inputs are rescaled so that
/// `mean(y²) == VCTK_AVG_ENERGY` before being passed to the
/// STFT. Skipping this step silently kills detection confidence.
pub const VCTK_AVG_ENERGY: f32 = 0.002_837_200_8;

/// Message dimensionality from the silentcipher trained model.
/// The decoder emits `MESSAGE_DIM` logit channels per time
/// frame. One symbol per frame is recovered by argmax over
/// these channels. Index 0 is the terminator; indices 1..=4 are
/// payload symbols (encoder-stored as raw symbol + 1).
pub const MESSAGE_DIM: usize = 5;

/// Length in symbols of one tiled copy of the message: 20
/// payload symbols + 1 terminator symbol.
pub const MESSAGE_LEN: usize = 21;

/// Confidence at or above which detection is reported as
/// `Detected`. Below this but above
/// [`CONFIDENCE_DEGRADED_THRESHOLD`] reports as `Degraded`.
///
/// v0.7 phase 7-pre audit #4: canonical definition now lives at
/// `provcheck::confidence::DETECTED_THRESHOLD`. This constant is
/// kept for backward compatibility (downstream callers including
/// the kit's per-family verify thresholds reference this name).
pub const CONFIDENCE_DETECTED_THRESHOLD: f32 = provcheck::confidence::DETECTED_THRESHOLD;

/// Confidence at or above which detection is reported as
/// `Degraded` (when not `Detected`). Below this reports as
/// `NotDetected` even if structural validity passed.
///
/// v0.7 phase 7-pre audit #4: canonical definition now lives at
/// `provcheck::confidence::DEGRADED_THRESHOLD`. Kept for backward
/// compatibility — see the matching note on
/// [`CONFIDENCE_DETECTED_THRESHOLD`].
pub const CONFIDENCE_DEGRADED_THRESHOLD: f32 = provcheck::confidence::DEGRADED_THRESHOLD;
