# v0.3.3 — silentcipher detection accuracy gap

## What we know

provcheck v0.3.2's Rust silentcipher decoder produces lower
confidence than a Python reference decoder running on the same
audio file with the same `.onnx` model. Concretely, on a
doomscroll.fm voice-mixdown MP3 that's been silentcipher-marked at
render time, the Python reference reports **0.95 confidence**
with the correct DFM payload `[0x44, 0x46, 0x4d, 0x01, 0x00]`.
provcheck reports **0.49 confidence** and the brand classifier
rejects below threshold, so the file shows as `not detected` in
the verifier output.

The gap is **not** structural. The Rust pipeline does the right
math:

- Reads the audio with symphonia
- VCTK energy rescale (`energy_ratio = 0.9999` on the test file)
- STFT with periodic Hann (now), n_fft=4096, hop=2048,
  center=true, reflect-pad
- ONNX inference via tract 0.21
- Argmax + per-position mode vote across tiles
- Terminator-aware unpack to 5 bytes

The terminator is found at position 0 (correct), and 14 of 21
message positions agree with the expected ground-truth payload.
We're recovering the right signal — just with enough per-frame
noise that the per-position vote goes the wrong way at 7
positions, dragging the confidence below the classifier's 0.50
threshold.

## What we're tracking down

The remaining gap is numerical, somewhere in the precision of the
intermediate values. Three candidate stages:

| Stage           | Likely cause                                    | Diagnostic                            |
|-----------------|-------------------------------------------------|---------------------------------------|
| 1. Audio decode | symphonia vs librosa+ffmpeg MP3 decoder         | STAGE 1 diff in decode_diff           |
| 3. STFT carrier | rustfft f32 SIMD path vs torch.stft             | STAGE 3 diff                          |
| 4. Model logits | tract 0.21 vs onnxruntime numerical accumulation | STAGE 4 diff (only if stages 1+3 OK)  |

## The investigation harness

Both ends produce a binary dump of every intermediate. The diff
tool reports per-stage L∞ / RMS differences. First stage above
tolerance is the bug.

### Rust side

```bash
cargo run --release -p provcheck-watermark --example decode_dump -- \
    path/to/file.mp3
# writes: path/to/file.rust.json  +  path/to/file.rust.bin
```

### Python side

Requires `pip install -r scripts/v0.3.3-python-reference.requirements.txt`.

```bash
python scripts/v0.3.3-python-reference.py path/to/file.mp3
# writes: path/to/file.python.json  +  path/to/file.python.bin
```

The Python script uses `librosa` (audio), `torch.stft` (matches
silentcipher's training), and `onnxruntime` (matches our model
file) — no dependency on silentcipher's actual source code. It's
an independent reference that anyone with the model checkpoint can
run.

### Compare

```bash
cargo run --release -p provcheck-watermark --example decode_diff -- \
    path/to/file.rust.json path/to/file.python.json
```

Output lists every stage with the magnitude of divergence and
flags the first one over tolerance:

```
[STAGE 1: audio decode]
  audio_pre_rescale     L∞=2.3e-05  RMS=4.1e-06   DIFF  ← MP3 decoder
[STAGE 2: VCTK rescale]
  audio_post_rescale    L∞=2.0e-05  RMS=3.6e-06   DIFF
[STAGE 3: STFT carrier]
  carrier (full)        L∞=8.4e-04  RMS=1.2e-04   OK
[STAGE 4: model logits]
  logits (full)         L∞=4.7e+00  RMS=1.1e+00   DIFF  ← model run divergence
```

(Numbers above are illustrative — we don't yet know what we'll
see when we actually run it.)

## What I'm changing in the Rust pipeline as part of v0.3.3

These were caught by close reading against silentcipher's source
and are correctness fixes, not optimisations:

1. **Periodic Hann window**, not symmetric. `torch.hann_window`
   defaults to `periodic=True`. (`stft.rs` was already updated.)

2. **Always tail-pad to a multiple of `WIN`**, even when the
   remainder is exactly 0. silentcipher's stft.py does
   `pad = win_len - x.shape[1] % win_len` which evaluates to
   `win_len` (a full extra window of zeros) in that edge case.
   v0.3.2 skipped the pad in that case. (`stft.rs` updated.)

Neither change explains the 0.95 → 0.49 confidence gap on its own
(empirically retested after the Hann change — no movement). They're
correctness fixes that bring the Rust pipeline closer to
bit-exact-with-silentcipher, narrowing the search space for the
real numerical divergence.

## Files in this investigation

```
docs/v0.3.3-detection-gap/
├── README.md                       (this file)
└── python-dump-protocol.md         (binary format spec)
scripts/
├── v0.3.3-python-reference.py      (Python reference decoder)
└── v0.3.3-python-reference.requirements.txt
crates/provcheck-watermark/examples/
├── decode_inspect.rs               (single-impl per-stage stats)
├── decode_dump.rs                  (writes the .rust.bin / .rust.json)
└── decode_diff.rs                  (compares two dumps)
```
