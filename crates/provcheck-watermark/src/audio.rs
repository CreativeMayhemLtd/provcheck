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

use rubato::{Resampler, SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction};
use symphonia::core::audio::{AudioBufferRef, Signal};
use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

use crate::hparams::SAMPLE_RATE;

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

    if src_sample_rate == SAMPLE_RATE {
        return Ok(mono);
    }
    resample(&mono, src_sample_rate, SAMPLE_RATE).map_err(|e| AudioError::Resample(e.to_string()))
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
        AudioBufferRef::U32(b) => downmix!(b, |s: u32| (s as f64 / 4_294_967_295.0 * 2.0 - 1.0)
            as f32),
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
    let mut resampler = SincFixedIn::<f32>::new(ratio, 2.0, params, chunk_size, 1)
        .map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity((src.len() as f64 * ratio) as usize + chunk_size);
    let mut pos = 0;
    while pos + chunk_size <= src.len() {
        let chunk = vec![src[pos..pos + chunk_size].to_vec()];
        let resampled = resampler
            .process(&chunk, None)
            .map_err(|e| e.to_string())?;
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
