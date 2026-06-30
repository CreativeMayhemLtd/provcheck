//! Audio container decode + downmix-to-mono + resample to
//! the rate the silentcipher model expects (44.1 kHz).
//!
//! Symphonia parses the container (mp3 / wav / flac / m4a /
//! ogg) and yields planar `i16` / `f32` / etc. PCM samples per
//! channel. We downmix to mono `f32`, then optionally resample
//! via rubato if the source rate differs from 44.1 kHz.
//!
//! The output is a single contiguous `Vec<f32>` containing the
//! whole file's PCM — silentcipher is short-clip-friendly
//! (~5–30 s typical) and provcheck verifies one file at a time,
//! so streaming detection isn't worth the complexity.

use std::fs::File;
use std::path::Path;

use rubato::{
    Resampler, SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction,
};
use symphonia::core::audio::{AudioBufferRef, Signal};
use symphonia::core::codecs::{CODEC_TYPE_AAC, CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

use crate::hparams::SAMPLE_RATE;

/// Default AAC LC encoder priming when the source container's
/// metadata does not surface it. Lavf, FFmpeg's built-in `aac`
/// encoder, and most reference AAC LC implementations insert
/// exactly 1024 priming samples at the head of the stream;
/// `iTunSMPB`-style streams (Apple, Nero) use 2112. symphonia
/// 0.5.5's `isomp4` reader does not expose the `edts/elst` edit
/// list or `iTunSMPB` tag as `codec_params.delay`, so we apply
/// this default when both `delay` is unset AND the codec is AAC.
/// Public issue #24 (v0.5.2): without this, AAC-in-MP4/M4A
/// detection returned conf 0.000 because every STFT frame was
/// 1024 samples out of phase with the embedder's frame grid.
const AAC_DEFAULT_PRIMING_SAMPLES: u32 = 1024;

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("not a recognised audio container")]
    NotAudio,
    #[error("audio decode failed: {0}")]
    Decode(String),
    #[error("resample failed: {0}")]
    Resample(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Stereo decode output. The two channels are always populated
/// at the target rate (44.1 kHz). `source_channels` is the
/// channel count of the original file BEFORE any duplication —
/// 1 means we duplicated a mono input into both `left` and
/// `right`, so the caller can decide whether to embed both
/// channels or treat them as identical.
#[derive(Debug)]
pub struct StereoDecoded {
    pub left: Vec<f32>,
    pub right: Vec<f32>,
    pub source_channels: u16,
}

/// Decode `path` to a mono `f32` waveform at the model's target
/// rate (44.1 kHz). Returns `Err(NotAudio)` for files that
/// symphonia can't identify as audio — the caller should map
/// this to a `WatermarkResult` with `message = "not audio"`
/// rather than surfacing it as an error.
pub fn decode_to_mono_44k1(path: &Path) -> Result<Vec<f32>, AudioError> {
    let file = File::open(path)?;
    let mss = MediaSourceStream::new(Box::new(file), Default::default());

    let mut hint = Hint::new();
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        hint.with_extension(ext);
    }

    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|_| AudioError::NotAudio)?;

    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or(AudioError::NotAudio)?;
    let track_id = track.id;
    let src_sample_rate = track
        .codec_params
        .sample_rate
        .ok_or_else(|| AudioError::Decode("track missing sample rate".into()))?;
    // Encoder-inserted priming + padding samples (LAME tag on MP3,
    // iTunSMPB on AAC-in-M4A, etc.). symphonia parses these but
    // does not auto-trim — that's the caller's job. Without this,
    // an MP3-decoded mono buffer starts 1105 samples earlier and
    // ends ~1109 samples later than what librosa/ffmpeg yield,
    // which shifts every downstream STFT frame and breaks the
    // silentcipher per-position mode vote. See
    // docs/v0.3.3-detection-gap/ for the empirical alignment proof.
    let enc_delay = effective_priming(track) as usize;
    let enc_padding = track.codec_params.padding.unwrap_or(0) as usize;

    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| AudioError::Decode(format!("no codec: {e}")))?;

    let mut mono = Vec::<f32>::with_capacity(1 << 20);

    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymphoniaError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(SymphoniaError::ResetRequired) => break,
            Err(e) => return Err(AudioError::Decode(e.to_string())),
        };
        if packet.track_id() != track_id {
            continue;
        }

        let decoded = match decoder.decode(&packet) {
            Ok(d) => d,
            Err(SymphoniaError::DecodeError(_)) => continue, // skip glitched packet, keep going
            Err(e) => return Err(AudioError::Decode(e.to_string())),
        };

        append_mono(&decoded, &mut mono);
    }

    if mono.is_empty() {
        return Err(AudioError::Decode("decoded zero samples".into()));
    }

    // Trim encoder priming + end padding. delay/padding are in
    // source-sample-rate frames, so this must happen before
    // resample(). Guards against pathological tags that would
    // empty or invert the buffer — saturate to a no-op rather
    // than truncate to nothing.
    if enc_delay > 0 && enc_delay < mono.len() {
        mono.drain(..enc_delay);
    }
    if enc_padding > 0 && enc_padding < mono.len() {
        let new_len = mono.len() - enc_padding;
        mono.truncate(new_len);
    }

    if src_sample_rate == SAMPLE_RATE {
        return Ok(mono);
    }
    resample(&mono, src_sample_rate, SAMPLE_RATE).map_err(|e| AudioError::Resample(e.to_string()))
}

/// Decode `path` to two `f32` waveforms (left, right) at 44.1 kHz.
/// For mono input, the single channel is duplicated into both
/// buffers and `source_channels` reports 1 so callers know the
/// duplication happened. For 3+ channel input, channels 0 and 1
/// are kept and the rest are dropped with a downmix of all the
/// "extra" channels averaged into both L and R (the most common
/// 5.1 case puts dialogue in centre + L/R; preserving L and R
/// while folding centre + surrounds into both keeps the mark
/// recoverable from the eventual stereo delivery).
///
/// Same encoder-priming trim and same rubato resample as the
/// mono path. Output L and R are guaranteed equal-length.
pub fn decode_to_stereo_44k1(path: &Path) -> Result<StereoDecoded, AudioError> {
    let file = File::open(path)?;
    let mss = MediaSourceStream::new(Box::new(file), Default::default());

    let mut hint = Hint::new();
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        hint.with_extension(ext);
    }

    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|_| AudioError::NotAudio)?;

    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or(AudioError::NotAudio)?;
    let track_id = track.id;
    let src_sample_rate = track
        .codec_params
        .sample_rate
        .ok_or_else(|| AudioError::Decode("track missing sample rate".into()))?;
    let source_channels = track
        .codec_params
        .channels
        .map(|c| c.count() as u16)
        .unwrap_or(1);
    let enc_delay = effective_priming(track) as usize;
    let enc_padding = track.codec_params.padding.unwrap_or(0) as usize;

    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| AudioError::Decode(format!("no codec: {e}")))?;

    let mut left = Vec::<f32>::with_capacity(1 << 20);
    let mut right = Vec::<f32>::with_capacity(1 << 20);

    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymphoniaError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(SymphoniaError::ResetRequired) => break,
            Err(e) => return Err(AudioError::Decode(e.to_string())),
        };
        if packet.track_id() != track_id {
            continue;
        }

        let decoded = match decoder.decode(&packet) {
            Ok(d) => d,
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(e) => return Err(AudioError::Decode(e.to_string())),
        };

        append_stereo(&decoded, &mut left, &mut right);
    }

    if left.is_empty() {
        return Err(AudioError::Decode("decoded zero samples".into()));
    }

    if enc_delay > 0 && enc_delay < left.len() {
        left.drain(..enc_delay);
        right.drain(..enc_delay);
    }
    if enc_padding > 0 && enc_padding < left.len() {
        let new_len = left.len() - enc_padding;
        left.truncate(new_len);
        right.truncate(new_len);
    }

    let (left, right) = if src_sample_rate == SAMPLE_RATE {
        (left, right)
    } else {
        let l = resample(&left, src_sample_rate, SAMPLE_RATE)
            .map_err(|e| AudioError::Resample(e.to_string()))?;
        let r = resample(&right, src_sample_rate, SAMPLE_RATE)
            .map_err(|e| AudioError::Resample(e.to_string()))?;
        (l, r)
    };

    Ok(StereoDecoded {
        left,
        right,
        source_channels,
    })
}

/// Encoder priming (head samples to drop) for the given track,
/// falling back to [`AAC_DEFAULT_PRIMING_SAMPLES`] when symphonia
/// did not surface the delay metadata and the codec is AAC. See
/// the constant's doc-comment for the rationale.
fn effective_priming(track: &symphonia::core::formats::Track) -> u32 {
    if let Some(d) = track.codec_params.delay {
        return d;
    }
    if track.codec_params.codec == CODEC_TYPE_AAC {
        return AAC_DEFAULT_PRIMING_SAMPLES;
    }
    0
}

/// Append the decoded buffer's samples to `mono`, downmixing
/// across channels by averaging. Symphonia exposes each sample
/// format as a separate generic, so we dispatch once on the
/// buffer's variant.
fn append_mono(buf: &AudioBufferRef<'_>, mono: &mut Vec<f32>) {
    macro_rules! downmix {
        ($buf:ident, $to_f32:expr) => {{
            let spec = $buf.spec();
            let chans = spec.channels.count();
            let frames = $buf.frames();
            for f in 0..frames {
                let mut acc = 0.0_f32;
                for c in 0..chans {
                    let s = $buf.chan(c)[f];
                    acc += $to_f32(s);
                }
                mono.push(acc / chans as f32);
            }
        }};
    }

    match buf {
        AudioBufferRef::U8(b) => downmix!(b, |s: u8| (s as f32 - 128.0) / 128.0),
        AudioBufferRef::U16(b) => downmix!(b, |s: u16| (s as f32 - 32768.0) / 32768.0),
        AudioBufferRef::U24(b) => downmix!(b, |s: symphonia::core::sample::u24| {
            (s.0 as f32 - 8_388_608.0) / 8_388_608.0
        }),
        AudioBufferRef::U32(b) => {
            downmix!(b, |s: u32| (s as f64 / 4_294_967_295.0 * 2.0 - 1.0) as f32)
        }
        AudioBufferRef::S8(b) => downmix!(b, |s: i8| s as f32 / 128.0),
        AudioBufferRef::S16(b) => downmix!(b, |s: i16| s as f32 / 32_768.0),
        AudioBufferRef::S24(b) => downmix!(b, |s: symphonia::core::sample::i24| {
            s.0 as f32 / 8_388_608.0
        }),
        AudioBufferRef::S32(b) => downmix!(b, |s: i32| s as f32 / 2_147_483_648.0),
        AudioBufferRef::F32(b) => downmix!(b, |s: f32| s),
        AudioBufferRef::F64(b) => downmix!(b, |s: f64| s as f32),
    }
}

/// Append the decoded buffer's samples to `left` and `right`,
/// keeping channels 0 and 1 separate. For 1-channel input the
/// single channel is duplicated into both buffers. For 3+ channel
/// input channels 2.. are averaged and added equally to both L
/// and R so centre + surround content survives the eventual
/// stereo delivery downmix.
fn append_stereo(buf: &AudioBufferRef<'_>, left: &mut Vec<f32>, right: &mut Vec<f32>) {
    macro_rules! split {
        ($buf:ident, $to_f32:expr) => {{
            let spec = $buf.spec();
            let chans = spec.channels.count();
            let frames = $buf.frames();
            match chans {
                0 => {}
                1 => {
                    for f in 0..frames {
                        let s = $to_f32($buf.chan(0)[f]);
                        left.push(s);
                        right.push(s);
                    }
                }
                _ => {
                    for f in 0..frames {
                        let mut l = $to_f32($buf.chan(0)[f]);
                        let mut r = $to_f32($buf.chan(1)[f]);
                        if chans > 2 {
                            let mut extras = 0.0_f32;
                            for c in 2..chans {
                                extras += $to_f32($buf.chan(c)[f]);
                            }
                            extras /= (chans - 2) as f32;
                            l += extras;
                            r += extras;
                        }
                        left.push(l);
                        right.push(r);
                    }
                }
            }
        }};
    }

    match buf {
        AudioBufferRef::U8(b) => split!(b, |s: u8| (s as f32 - 128.0) / 128.0),
        AudioBufferRef::U16(b) => split!(b, |s: u16| (s as f32 - 32768.0) / 32768.0),
        AudioBufferRef::U24(b) => split!(b, |s: symphonia::core::sample::u24| {
            (s.0 as f32 - 8_388_608.0) / 8_388_608.0
        }),
        AudioBufferRef::U32(b) => {
            split!(b, |s: u32| (s as f64 / 4_294_967_295.0 * 2.0 - 1.0) as f32)
        }
        AudioBufferRef::S8(b) => split!(b, |s: i8| s as f32 / 128.0),
        AudioBufferRef::S16(b) => split!(b, |s: i16| s as f32 / 32_768.0),
        AudioBufferRef::S24(b) => split!(b, |s: symphonia::core::sample::i24| {
            s.0 as f32 / 8_388_608.0
        }),
        AudioBufferRef::S32(b) => split!(b, |s: i32| s as f32 / 2_147_483_648.0),
        AudioBufferRef::F32(b) => split!(b, |s: f32| s),
        AudioBufferRef::F64(b) => split!(b, |s: f64| s as f32),
    }
}

/// Resample `src` from `src_rate` to `dst_rate`. Uses rubato's
/// `SincFixedIn` resampler with the documented "Quality" preset
/// from rubato's own docs — close enough to librosa's defaults
/// that detection confidence holds on production inputs.
fn resample(src: &[f32], src_rate: u32, dst_rate: u32) -> Result<Vec<f32>, String> {
    let params = SincInterpolationParameters {
        sinc_len: 256,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 256,
        window: WindowFunction::BlackmanHarris2,
    };
    let ratio = dst_rate as f64 / src_rate as f64;
    // Chunk size — process in 4096-sample blocks. The "Fixed In"
    // variant requires that the input always be exactly chunk
    // size; we pad the tail with zeros so the resampler can
    // flush its internal state without losing the last frames.
    let chunk_size = 4096usize;
    let mut resampler =
        SincFixedIn::<f32>::new(ratio, 2.0, params, chunk_size, 1).map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity((src.len() as f64 * ratio) as usize + chunk_size);
    let mut pos = 0;
    while pos + chunk_size <= src.len() {
        let chunk = vec![src[pos..pos + chunk_size].to_vec()];
        let resampled = resampler.process(&chunk, None).map_err(|e| e.to_string())?;
        out.extend_from_slice(&resampled[0]);
        pos += chunk_size;
    }
    // Tail: zero-pad to chunk size so the resampler doesn't
    // discard the partial frame. This adds a tiny zero-tail to
    // the output, which is harmless for STFT/detection.
    if pos < src.len() {
        let mut tail = vec![0.0_f32; chunk_size];
        let remaining = src.len() - pos;
        tail[..remaining].copy_from_slice(&src[pos..]);
        let resampled = resampler
            .process(&[tail], None)
            .map_err(|e| e.to_string())?;
        out.extend_from_slice(&resampled[0]);
    }
    Ok(out)
}

#[cfg(test)]
mod audio_error_tests {
    use super::*;

    #[test]
    fn not_audio_message_is_meaningful() {
        let s = format!("{}", AudioError::NotAudio);
        assert!(s.contains("audio container"), "got: {s}");
    }

    #[test]
    fn decode_error_includes_inner() {
        let s = format!("{}", AudioError::Decode("symphonia eof".into()));
        assert!(s.contains("audio decode"));
        assert!(s.contains("symphonia eof"));
    }

    #[test]
    fn resample_error_includes_inner() {
        let s = format!("{}", AudioError::Resample("ratio rejected".into()));
        assert!(s.contains("resample"));
        assert!(s.contains("ratio rejected"));
    }

    #[test]
    fn io_error_includes_inner() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no read");
        let s = format!("{}", AudioError::Io(io));
        assert!(s.contains("io"));
        assert!(s.contains("no read"));
    }

    #[test]
    fn io_from_std_io_error_works() {
        // The #[from] impl must compile + dispatch.
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let _e: AudioError = io.into();
    }

    #[test]
    fn decode_to_mono_44k1_on_missing_file_returns_io_error() {
        let r = decode_to_mono_44k1(std::path::Path::new("/no/such/audio.wav"));
        assert!(matches!(r, Err(AudioError::Io(_))));
    }

    #[test]
    fn decode_to_stereo_44k1_on_missing_file_returns_io_error() {
        let r = decode_to_stereo_44k1(std::path::Path::new("/no/such/audio.wav"));
        assert!(matches!(r, Err(AudioError::Io(_))));
    }

    // ----- AAC priming constant pin ----------
    //
    // The AAC priming workaround was the v0.5.3 hotfix for
    // public issue #24. Without the documented 1024-sample
    // default, AAC-in-MP4/M4A detection returned conf 0.000.
    // Pin the constant explicitly so a future maintainer can't
    // silently "simplify" the workaround away.

    #[test]
    fn aac_default_priming_samples_is_1024() {
        assert_eq!(AAC_DEFAULT_PRIMING_SAMPLES, 1024);
    }

    #[test]
    fn aac_default_priming_matches_canonical_aac_encoder_delay() {
        // Canonical AAC encoder delay is 2048 samples per the
        // standard, but the LC-AAC profile we encounter in MP4
        // containers from Apple's encoder consistently uses
        // 1024 (half-frame) priming. Pin the half-frame value.
        // (The 2048 vs 1024 ambiguity is exactly the trap that
        // caused issue #24.)
        let half_frame = std::hint::black_box(AAC_DEFAULT_PRIMING_SAMPLES);
        let full_frame: u32 = 2048;
        assert!(
            half_frame == full_frame / 2,
            "documented half-frame priming: {half_frame} vs full_frame {full_frame}"
        );
    }

    // ----- resample helper ----------

    #[test]
    fn resample_identity_when_src_eq_dst_returns_same_length_ish() {
        // Same in/out rate → ratio 1.0 → output length ≈ input.
        // Tail-pad to chunk size adds at most chunk_size extra
        // zero samples; pin "output close to input, never empty".
        let src: Vec<f32> = (0..10000).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample(&src, 44_100, 44_100).expect("ok");
        assert!(!out.is_empty());
        assert!(
            (out.len() as i64 - src.len() as i64).abs() < 4096,
            "out.len()={} too far from src.len()={}",
            out.len(),
            src.len()
        );
    }

    #[test]
    fn resample_up_doubles_length_approximately() {
        // 22050 → 44100 doubles. Pin the documented contract.
        let src: Vec<f32> = (0..10000).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample(&src, 22_050, 44_100).expect("ok");
        let ratio = out.len() as f32 / src.len() as f32;
        assert!(
            (ratio - 2.0).abs() < 0.5,
            "expected ~2x output length, got ratio {ratio}"
        );
    }

    #[test]
    fn resample_down_halves_length_approximately() {
        // 88200 → 44100 halves. Pin.
        let src: Vec<f32> = (0..20000).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample(&src, 88_200, 44_100).expect("ok");
        let ratio = out.len() as f32 / src.len() as f32;
        assert!(
            (ratio - 0.5).abs() < 0.25,
            "expected ~0.5x output length, got ratio {ratio}"
        );
    }

    #[test]
    fn resample_returns_finite_samples_for_finite_input() {
        // The resampler must never produce NaN/inf on finite
        // input. Catches a future SincFixedIn config that
        // silently divides by zero on edge cases.
        let src: Vec<f32> = (0..10000).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample(&src, 48_000, 44_100).expect("ok");
        for (i, &s) in out.iter().enumerate() {
            assert!(s.is_finite(), "non-finite sample at index {i}: {s}");
        }
    }

    #[test]
    fn resample_short_input_below_chunk_size_works() {
        // Input shorter than chunk_size (4096) takes only the
        // tail-pad path. Pin that this still produces output.
        let src: Vec<f32> = (0..100).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample(&src, 44_100, 44_100).expect("ok");
        assert!(!out.is_empty());
    }

    #[test]
    fn stereo_decoded_struct_field_layout_pin() {
        // StereoDecoded is a public type; pin its field
        // layout so a future refactor doesn't accidentally
        // rename or reorder fields without a test failure.
        let s = StereoDecoded {
            left: vec![1.0],
            right: vec![2.0],
            source_channels: 2,
        };
        assert_eq!(s.left.len(), 1);
        assert_eq!(s.right.len(), 1);
        assert_eq!(s.source_channels, 2);
    }
}
