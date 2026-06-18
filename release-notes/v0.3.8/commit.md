v0.3.8: silentcipher watermark EMBEDDING — close the producer side

Closes the doomscroll.fm-reported production block where ffmpeg's
loudness-normalisation step on mixed episodes destroyed the
render-time silentcipher mark. Until this release, provcheck-kit
could sign and publish — but it couldn't re-stamp audio. Now it can.

New CLI subcommand

  provcheck-kit watermark <input> -o <output.wav> \
      [--payload <10-hex-chars>] [--sdr-db <dB>] [--overwrite]

Decode any audio symphonia handles (mp3 / wav / flac / m4a / ogg /
opus), embed a 5-byte silentcipher payload, and write a watermarked
WAV. Re-encode externally to MP3/AAC via ffmpeg if needed — the kit
deliberately doesn't bundle an MP3 encoder to keep the binary small
and the supply chain narrow.

Default payload is `44 46 4d 01 00` (DFM\x01\x00 = doomscroll.fm).

Pipeline

Mirrors silentcipher's `encode_wav` (server.py:272-348) line-for-line:

  audio → VCTK rescale → forward STFT (mag + phase)
        → letters_encoding (payload → tile-tiled message tensor)
        → transform_message (linear 5→1024 + zero-pad to 2049)
        → chunked encoder ONNX (enc_c + dec_c fused)
        → utterance-level norm scalar + negate + relu(+carrier)
        → inverse STFT (using ORIGINAL phase)
        → VCTK de-rescale
        → WAV write

Chunked along the time axis at the same CHUNK_T_FRAMES=256 boundary
the v0.3.7 detector uses, so the peak RSS during embedding is also
~1.5 GB regardless of audio length. Hour-long episodes are
supported.

End-to-end verified

  kit watermark examples/rAIdio.bot-sample.mp3 -o out.wav
    → 49.55s wall-clock on 60s audio (0.82x real-time)
    → achieved SDR 50.8 dB

  provcheck out.wav
    → silentcipher: detected — doomscroll.fm (88% confidence)
    → payload: 44464d0100

ONNX export

`scripts/export-silentcipher-encoder.py` exports the silentcipher
44.1k encoder + carrier-decoder graph to a single ONNX. Run once
locally at build time; the produced model ships embedded in the
binary via include_bytes! at compile time. License: silentcipher is
MIT (Sony Research Inc., model weights + code) — compatible with
the workspace policy in WATERMARK_LICENSE_POLICY.md.

Two pieces of the encoder graph stay in Rust because tract 0.21
can't analyse their ONNX nodes:

  - `transform_message`'s F.pad (linear projection 5→1024, then
    zero-pad to FREQ_BINS). The 20 KB of linear weight + 4 KB of
    bias ship alongside the ONNX as binary blobs and are read at
    runtime via include_bytes!.
  - The utterance-level normalisation scalar (multiplier from
    sqrt(mean(carrier^2)) over the full pre-inference carrier).
    Must be computed from the un-chunked carrier, so it can't
    live inside per-chunk inference.

New modules

  crates/provcheck-watermark/src/encode.rs
    The producer-side library: `embed(waveform, payload, sdr_db)`
    returns a watermarked waveform of the same length.

  crates/provcheck-watermark/src/stft.rs (extended)
    `waveform_to_spectrum()` — forward STFT returning mag + phase.
    `spectrum_to_waveform()` — inverse STFT (overlap-add + window
    correction). Round-trips at 135 dB SDR (f32 round-off floor)
    on the interior.

  crates/provcheck-watermark/examples/embed_roundtrip.rs
    End-to-end test: decode audio → embed → write WAV →
    run detector → confirm payload + brand. Used during
    development; also useful as a smoke test for future
    silentcipher model bumps.

  crates/provcheck-kit/src/commands/mod.rs (Watermark subcommand)
    Thin CLI wrapper around encode::embed + symphonia decode +
    hound WAV writer.

Diagnostic scripts

  scripts/export-silentcipher-encoder.py
  scripts/diagnose-embed-mismatch.py

The diagnose script marks synthetic audio with silentcipher's
Python encode_wav and writes a WAV — useful for triangulating
whether a detection regression is on the embed side or the
detect side.

Wall-clock characteristics

On the 60-second rAIdio.bot music sample (Windows release build):
  embed:  49.55 s (0.82x real-time)
  detect: 93.71 s (1.55x real-time, also chunked)

Linux production runners are typically 2-4x faster than this
Windows dev box, so doomscroll's container should see embed times
comfortably under 30s per minute of audio.

Memory characteristics

Same as v0.3.7's chunked detect: peak RSS ~1.5 GB regardless of
audio length. Verified by the same `examples/memory_check.rs`
infrastructure shipped in v0.3.7.

Tests

29 watermark lib tests (was 27; added STFT-with-phase round-trip
test + letters_encoding tests). 6 watermark integration tests.
27 kit unit tests (added 3 payload-parsing tests for the new
watermark subcommand). All workspace tests green.

Wire format

No CLI behaviour or wire-format changes on the verifier side.
The new subcommand is purely additive.

What this unblocks for doomscroll.fm

Pipeline (existing):
  1. Render voice + music stems with silentcipher at source.
  2. ffmpeg mix + loudness normalisation.
  3. (mark destroyed — confirmed by their bug report.)

Pipeline (with v0.3.8):
  1. Render voice + music stems with silentcipher at source.
  2. ffmpeg mix + loudness normalisation.
  3. provcheck-kit watermark mixed.mp3 -o mixed.wav
  4. ffmpeg mixed.wav -c:a libmp3lame -b:a 192k final.mp3
     (or whatever delivery codec they use)
  5. final.mp3 carries a detectable doomscroll.fm mark.

Doomscroll team: bump your container's ARG PROVCHECK_VERSION to
v0.3.8 and add a `kit watermark` step between your ffmpeg normalize
and ffmpeg encode passes.
