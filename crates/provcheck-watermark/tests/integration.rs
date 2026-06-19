//! Integration tests for `provcheck-watermark`.
//!
//! These exercise the public API as a downstream crate would see
//! it. Real watermarked-audio tests are gated behind `#[ignore]`
//! until the silentcipher ONNX model lands at
//! `models/silentcipher-decoder.onnx`.

use provcheck_watermark::{
    WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus, detect,
};
use std::io::Write;

fn write_tempfile(suffix: &str, bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .expect("create tempfile");
    f.write_all(bytes).expect("write tempfile");
    f
}

#[test]
fn public_api_uses_re_exported_core_types() {
    // The crate re-exports WatermarkResult / WatermarkKind from
    // provcheck. Caller code shouldn't need to depend on both
    // crates to read a result.
    let _: WatermarkKind = WatermarkKind::SilentCipher;
}

#[test]
fn png_file_reports_not_audio() {
    let f = write_tempfile(".png", b"\x89PNG\r\n\x1a\nfake");
    let r: WatermarkResult = detect(f.path()).expect("detect succeeds");
    assert!(!r.detected);
    assert_eq!(r.confidence, 0.0);
    assert!(matches!(r.kind, WatermarkKind::SilentCipher));
    assert_eq!(r.message.as_deref(), Some("not audio"));
    assert!(r.payload.is_none());
}

#[test]
fn fake_wav_decodes_to_not_detected_not_an_error() {
    // The extension sniff lets it through, but symphonia can't
    // make sense of the bytes — the detector must report a
    // graceful NotDetected with a descriptive message, never
    // panic or surface as `Err`.
    let f = write_tempfile(".wav", b"RIFF\0\0\0\0WAVEfmt fakebytes");
    let r = detect(f.path()).expect("detect succeeds");
    assert!(!r.detected);
    assert!(matches!(r.status, WatermarkStatus::NotDetected));
    assert!(r.message.is_some());
}

#[test]
fn missing_file_surfaces_io_error() {
    let err = detect(std::path::Path::new(
        "definitely_does_not_exist_8675309.mp3",
    ))
    .unwrap_err();
    assert!(matches!(err, provcheck_watermark::Error::Io(_)));
}

#[test]
fn result_serializes_to_json_with_expected_shape() {
    let r = WatermarkResult {
        kind: WatermarkKind::SilentCipher,
        status: WatermarkStatus::Detected,
        detected: true,
        confidence: 0.97,
        payload: Some(vec![68, 70, 77, 1, 0]),
        brand: Some(WatermarkBrand::Doomscroll),
        message: None,
        marked_regions: None,
    };
    let json = serde_json::to_string(&r).expect("serialize");
    assert!(json.contains("\"kind\":\"silent_cipher\""));
    assert!(json.contains("\"status\":\"detected\""));
    assert!(json.contains("\"detected\":true"));
    assert!(json.contains("\"confidence\":0.97"));
    assert!(json.contains("\"brand\""));
    assert!(json.contains("\"doomscroll\""));
    // `message: None` is dropped by the skip_serializing_if
    // attribute; `payload: Some(...)` round-trips intact.
    assert!(!json.contains("\"message\""));
    assert!(json.contains("\"payload\""));
}

/// Positive control: a freshly silentcipher-embedded waveform
/// is detected end-to-end through the full pipeline (decode →
/// encode → WAV writer → symphonia → STFT → tract → decode),
/// with the payload recovered intact and confidence above the
/// model's healthy-detection threshold.
///
/// Cover signal is `examples/rAIdio.bot-sample.mp3` checked into
/// the workspace root. silentcipher was trained on speech /
/// natural audio (VCTK); synthetic broadband noise sits well
/// outside that distribution and the encoder produces a mark
/// that the decoder cannot recover even at high SDR. Real audio
/// avoids that problem entirely and keeps the test honest about
/// what production callers actually feed the embed path.
///
/// Also asserts that `marked_regions` populates — the v0.4.2
/// per-tile localisation path runs on every detected result.
#[test]
fn real_silentcipher_embed_roundtrips_to_detection() {
    use provcheck_watermark::{audio, encode};

    let cover_path = workspace_example("rAIdio.bot-sample.mp3");
    if !cover_path.exists() {
        // The workspace sample is checked in, but be defensive
        // about exotic shallow-clone setups. Skipping is better
        // than a misleading panic on a missing file.
        eprintln!(
            "skipping: cover sample not present at {}",
            cover_path.display()
        );
        return;
    }

    let cover = audio::decode_to_mono_44k1(&cover_path).expect("decode cover");
    assert!(
        cover.len() >= 44_100 * 5,
        "cover must be ≥ 5 s of audio; got {} samples",
        cover.len()
    );

    // doomscroll.fm payload: "DFM" + schema=1 + reserved=0.
    let payload: [u8; 5] = [0x44, 0x46, 0x4D, 0x01, 0x00];

    let marked = encode::embed(&cover, payload, None).expect("embed succeeds");
    assert_eq!(marked.len(), cover.len(), "embed must preserve length");

    let tempfile = write_float_wav(&marked, 44_100);
    let r = detect(tempfile.path()).expect("detect succeeds on roundtrip fixture");

    assert!(
        r.detected,
        "embedded silentcipher mark must be detected end-to-end; got {:?}",
        r
    );
    assert!(
        matches!(r.status, WatermarkStatus::Detected),
        "expected Detected status, got {:?}",
        r.status
    );
    assert!(
        r.confidence > 0.8,
        "expected confidence > 0.8 on a clean roundtrip, got {}",
        r.confidence
    );
    assert_eq!(
        r.payload.as_deref(),
        Some(payload.as_slice()),
        "decoder must recover the embedded payload"
    );
    assert!(
        matches!(r.brand, Some(WatermarkBrand::Doomscroll)),
        "DFM payload must map to Doomscroll, got {:?}",
        r.brand
    );
    assert!(
        r.marked_regions.is_some(),
        "v0.4.2 localisation must populate marked_regions on detected results; got None"
    );
}

/// Resolve a path relative to the workspace `examples/` directory
/// from inside an integration test. `CARGO_MANIFEST_DIR` is set
/// to the crate root (`crates/provcheck-watermark`); walking up
/// two levels gets us back to the workspace root.
fn workspace_example(name: &str) -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above CARGO_MANIFEST_DIR")
        .join("examples")
        .join(name)
}

/// Real unmarked audio is reported as `NotDetected` with the
/// zero-confidence sentinel. Exercises the full pipeline end-
/// to-end (symphonia decode → STFT → tract inference →
/// back-end decode) on real audio bytes — proves the
/// structural-validity check rejects content that doesn't
/// carry a silentcipher message.
///
/// The fixture is generated at test time via `hound` so we
/// don't carry a binary blob in the repo and so the test is
/// fully self-contained.
#[test]
fn real_unmarked_audio_is_not_detected() {
    let f = synth_unmarked_wav(10.0);
    let r = detect(f.path()).expect("detect succeeds on synth unmarked audio");
    assert!(
        !r.detected,
        "synth unmarked audio should not be flagged: {:?}",
        r
    );
    assert!(
        matches!(r.status, WatermarkStatus::NotDetected),
        "expected NotDetected status, got {:?}",
        r.status
    );
    assert_eq!(
        r.confidence, 0.0,
        "unmarked content uses the 0.0 sentinel — structural-validity \
         short-circuits before computing the confidence statistic"
    );
}

/// Write a mono 32-bit float WAV at 44.1 kHz to a tempfile.
fn write_float_wav(samples: &[f32], sample_rate: u32) -> tempfile::NamedTempFile {
    let f = tempfile::Builder::new()
        .suffix(".wav")
        .tempfile()
        .expect("tempfile");
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let mut writer = hound::WavWriter::create(f.path(), spec).expect("create wav");
    for s in samples {
        writer.write_sample(*s).expect("write sample");
    }
    writer.finalize().expect("finalize wav");
    f
}

/// Synthesise a mono 44.1 kHz WAV with a mix of audible sine
/// tones — enough signal that the VCTK rescale doesn't trip
/// the silent-input fast-path, but not actual content the
/// model has been trained on. Long enough to produce many
/// STFT tiles (10 s × 44.1 kHz ÷ 2048 hop ≈ 215 frames → 10
/// tiles of 21 symbols each, easily past the `min_tiles` of 1).
fn synth_unmarked_wav(duration_s: f32) -> tempfile::NamedTempFile {
    let f = tempfile::Builder::new()
        .suffix(".wav")
        .tempfile()
        .expect("tempfile");
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(f.path(), spec).expect("create wav");
    let n = (duration_s * 44_100.0) as usize;
    let two_pi = 2.0_f32 * std::f32::consts::PI;
    for i in 0..n {
        let t = i as f32 / 44_100.0;
        // Three-tone chord — plenty of spectral energy across
        // the band so the model sees a real signal, but no
        // silentcipher embedding has touched it.
        let s = 0.20 * (two_pi * 440.0 * t).sin()
            + 0.15 * (two_pi * 880.0 * t).sin()
            + 0.10 * (two_pi * 1320.0 * t).sin();
        writer
            .write_sample((s.clamp(-1.0, 1.0) * 30_000.0) as i16)
            .expect("write sample");
    }
    writer.finalize().expect("finalize wav");
    f
}
