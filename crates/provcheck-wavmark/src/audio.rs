//! Audio decode + downmix-to-mono + resample to 16 kHz (WavMark's
//! training rate). Mirrors `provcheck-audioseal::audio` byte-for-byte —
//! both detectors share the same target rate; only the model
//! parameters differ.

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

/// Target sample rate for WavMark. The 32-bit decoder is trained at
/// 16 kHz; passing a different rate silently breaks the watermark.
pub const SAMPLE_RATE: u32 = 16_000;

/// Default AAC LC encoder priming when the source container does
/// not surface it. See the matching constant in
/// `provcheck-watermark/src/audio.rs` for the rationale. Public
/// issue #24 (v0.5.2).
const AAC_DEFAULT_PRIMING_SAMPLES: u32 = 1024;

fn effective_priming(track: &symphonia::core::formats::Track) -> u32 {
    if let Some(d) = track.codec_params.delay {
        return d;
    }
    if track.codec_params.codec == CODEC_TYPE_AAC {
        return AAC_DEFAULT_PRIMING_SAMPLES;
    }
    0
}

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

/// Decode `path` to a mono f32 waveform at WavMark's target rate
/// (16 kHz). LAME priming + end padding are trimmed when the input
/// is an MP3.
pub fn decode_to_mono_16k(path: &Path) -> Result<Vec<f32>, AudioError> {
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
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(e) => return Err(AudioError::Decode(e.to_string())),
        };

        append_mono(&decoded, &mut mono);
    }

    if mono.is_empty() {
        return Err(AudioError::Decode("decoded zero samples".into()));
    }

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

/// Stereo decode output. The two channels are always populated at
/// the target rate (16 kHz). `source_channels` is the channel
/// count of the original file BEFORE any duplication.
///
/// v0.7 phase 7-pre audit #1: parity with
/// `provcheck-watermark::audio::StereoDecoded` and
/// `provcheck-audioseal::audio::StereoDecoded`. Used by the kit
/// when `--channels stereo` routes through wavmark.
#[derive(Debug)]
pub struct StereoDecoded {
    pub left: Vec<f32>,
    pub right: Vec<f32>,
    pub source_channels: u16,
}

/// Decode `path` to two `f32` waveforms (left, right) at 16 kHz.
/// Mirrors `provcheck-audioseal::audio::decode_to_stereo_16k`
/// byte-for-byte — both crates share the same target rate; only
/// the model parameters differ.
///
/// v0.7 phase 7-pre audit #1.
pub fn decode_to_stereo_16k(path: &Path) -> Result<StereoDecoded, AudioError> {
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

pub fn resample(src: &[f32], src_rate: u32, dst_rate: u32) -> Result<Vec<f32>, String> {
    let params = SincInterpolationParameters {
        sinc_len: 256,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 256,
        window: WindowFunction::BlackmanHarris2,
    };
    let ratio = dst_rate as f64 / src_rate as f64;
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
