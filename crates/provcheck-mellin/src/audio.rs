//! Audio file I/O for the mellin CLI.
//!
//! Read side: any format symphonia decodes (WAV, MP3, AAC, FLAC, M4A, OGG),
//! **deinterleaved to per-channel** i16 LE PCM, so a leaked copy can be read
//! back whatever container it arrived in and every channel's mark can be voted.
//!
//! Write side: 16-bit interleaved WAV via hound (mono or multi-channel), the
//! lossless home format for the embedded mark. Marking each channel keeps a
//! stereo master stereo rather than collapsing it to mono.

use hound::{SampleFormat, WavSpec, WavWriter};
use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::errors::Error as SymError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

/// Decode any supported audio file into per-channel i16 LE PCM streams.
/// Returns `(channels, sample_rate)` where `channels[c]` is channel `c`'s LE
/// bytes. A mono file yields a single stream.
pub fn decode_planar_i16le(path: &str) -> Result<(Vec<Vec<u8>>, u32), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mss = MediaSourceStream::new(Box::new(file), Default::default());

    let mut hint = Hint::new();
    if let Some(ext) = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
    {
        hint.with_extension(ext);
    }
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| format!("{path}: unrecognized audio format: {e}"))?;
    let mut format = probed.format;

    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
        .ok_or_else(|| format!("{path}: no decodable audio track"))?;
    let track_id = track.id;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| format!("{path}: no decoder: {e}"))?;

    let mut sample_rate = track.codec_params.sample_rate.unwrap_or(44_100);
    let mut nch = 1usize;
    let mut planar: Vec<Vec<i16>> = Vec::new();
    let mut sbuf: Option<SampleBuffer<i16>> = None;

    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymError::IoError(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(SymError::ResetRequired) => break,
            Err(e) => return Err(format!("{path}: read: {e}")),
        };
        if packet.track_id() != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(audio_buf) => {
                if sbuf.is_none() {
                    let spec = *audio_buf.spec();
                    sample_rate = spec.rate;
                    nch = spec.channels.count().max(1);
                    planar = vec![Vec::new(); nch];
                    sbuf = Some(SampleBuffer::<i16>::new(audio_buf.capacity() as u64, spec));
                }
                let sb = sbuf.as_mut().unwrap();
                sb.copy_interleaved_ref(audio_buf);
                for frame in sb.samples().chunks_exact(nch) {
                    for (c, &s) in frame.iter().enumerate() {
                        planar[c].push(s);
                    }
                }
            }
            Err(SymError::DecodeError(_)) => continue,
            Err(e) => return Err(format!("{path}: decode: {e}")),
        }
    }

    if planar.is_empty() || planar[0].is_empty() {
        return Err(format!("{path}: decoded to zero samples"));
    }
    let channels = planar
        .into_iter()
        .map(|ch| {
            let mut bytes = Vec::with_capacity(ch.len() * 2);
            for s in ch {
                bytes.extend_from_slice(&s.to_le_bytes());
            }
            bytes
        })
        .collect();
    Ok((channels, sample_rate))
}

/// Write per-channel i16 LE PCM streams as an interleaved 16-bit WAV. All
/// channel streams must be the same length.
pub fn write_wav_i16le(path: &str, channels: &[Vec<u8>], sample_rate: u32) -> Result<(), String> {
    if channels.is_empty() {
        return Err(format!("{path}: no channels to write"));
    }
    let nch = channels.len();
    let frames = channels[0].len() / 2;
    if channels.iter().any(|c| c.len() / 2 != frames) {
        return Err(format!("{path}: channel length mismatch"));
    }
    let spec = WavSpec {
        channels: nch as u16,
        sample_rate,
        bits_per_sample: 16,
        sample_format: SampleFormat::Int,
    };
    let mut writer = WavWriter::create(path, spec).map_err(|e| format!("create {path}: {e}"))?;
    for i in 0..frames {
        for ch in channels {
            let s = i16::from_le_bytes([ch[2 * i], ch[2 * i + 1]]);
            writer
                .write_sample(s)
                .map_err(|e| format!("{path}: write: {e}"))?;
        }
    }
    writer
        .finalize()
        .map_err(|e| format!("{path}: finalize: {e}"))?;
    Ok(())
}
