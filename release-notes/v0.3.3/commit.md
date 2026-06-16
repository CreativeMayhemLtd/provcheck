v0.3.3: silentcipher detector accuracy — honor MP3 encoder delay

Closes the detection-confidence gap on LAME-encoded MPEG inputs.
On a known-marked voices-mixdown MP3, the Python reference reports
0.83 confidence with the correct DFM payload. v0.3.2 reported 0.49
with garbage payload, and the brand classifier rejected it as
not-detected. v0.3.3 reports 0.83 with the same payload, matching
the reference to the f32 round-off floor.

The bug

symphonia 0.5 parses the LAME info tag's encoder-delay (priming) and
end-padding fields into `CodecParameters.delay` / `.padding`, but does
NOT auto-trim — by design; the caller is expected to do it.
provcheck-watermark's audio.rs wasn't reading either field, so every
MP3 was decoded with 1105 samples of leading priming silence + ~1109
samples of trailing padding still attached. That shifted every
downstream STFT frame, broke silentcipher's per-position mode vote
across tiles, and dragged confidence below the classifier's
acceptance threshold.

librosa, ffmpeg, libsndfile, iTunes, and every other reference MP3
decoder trim these samples per the LAME spec. Bringing
provcheck-watermark into compliance was a one-call addition:

  let enc_delay = track.codec_params.delay.unwrap_or(0) as usize;
  let enc_padding = track.codec_params.padding.unwrap_or(0) as usize;
  // ... after decode loop:
  if enc_delay > 0 && enc_delay < mono.len() { mono.drain(..enc_delay); }
  if enc_padding > 0 && enc_padding < mono.len() {
      mono.truncate(mono.len() - enc_padding);
  }

The diagnosis

decode_diff on a known-marked file flagged STAGE 1 (audio decode) at
L∞=0.74, RMS=0.084 — orders of magnitude beyond the 1e-5 tolerance
that downstream noise sets. A follow-up alignment search
(examples/align_check.rs) tried integer shifts k ∈ [0, 2214] of the
Rust audio against the Python audio and found a single minimum at
k=1105 with RMSD=2.3e-8 (f32 round-off floor) — the exact, canonical
LAME priming-frame count. That fingerprinted the bug as encoder-delay
trim, not a codec-level numerical difference.

Also in v0.3.3

Two structural alignments to silentcipher's reference, both caught
by source audit during the investigation:

- stft.rs Hann window: symmetric (1/(n-1)) → periodic (1/n). Matches
  torch.hann_window default, which silentcipher's training uses.
- stft.rs tail-pad: always pad to a multiple of WIN, even when the
  remainder is 0 (silentcipher's stft.py always pads). The v0.3.2
  conditional pad skipped this edge case.

Neither moved the confidence needle alone — both were swamped by the
MP3-decoder bug — but they're correctness fixes that bring the Rust
pipeline bit-exact with silentcipher's reference and rule out cascade
suspects from future investigations. Both lock-in tested.

Diagnostic harness shipped alongside

- examples/decode_dump.rs — dumps every Rust-side intermediate
  (audio pre/post rescale, carrier, logits, argmax, mode_per_pos,
  payload symbols, payload bytes) as paired .json + .bin.
- examples/decode_diff.rs — per-stage L∞/RMS divergence vs a
  reference dump, with per-bin and per-time-frame breakdowns when
  STAGE 3 (carrier) diverges past tolerance.
- examples/align_check.rs — integer-shift alignment search;
  identifies sample offsets between two audio decodes. The tool
  that fingerprinted the encoder delay.
- scripts/v0.3.3-python-reference.py — Python reference decoder
  using librosa + torch.stft + onnxruntime against our same .onnx.
  No silentcipher source dependency.
- scripts/v0.3.3-investigate.sh — one-command driver.
- docs/v0.3.3-detection-gap/ — investigation overview, binary-dump
  protocol spec, MP3 decoder survey.

The harness stays in-repo as the regression suite if a future
symphonia upgrade, tract bump, or model swap reopens the gap.

Test surface

26 watermark unit tests (was 25; added the always-pad regression
test), 6 watermark integration tests, all green. Workspace test
counts unchanged otherwise.

Wire format

No changes. Report shape is identical; the on-disk attestation,
signing-key record, and lexicon formats are untouched. Drop-in
upgrade for any 0.3.x consumer.
