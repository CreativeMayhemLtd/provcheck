# Python-side dump protocol — v0.3.3 detection-gap investigation

The Rust silentcipher decoder (provcheck v0.3.2) produces ~0.49
confidence on a known-marked file where the Python reference
hits ~0.95 with the correct DFM payload. The pipeline is
structurally correct (terminator found at the right position,
14 of 21 message positions match); the gap is somewhere in the
numerical precision of intermediate values.

To pin it down we run the same audio through both decoders, dump
every intermediate to disk in the same format, and diff stage by
stage. The first stage that diverges meaningfully (above f32
round-off tolerance) is the bug.

## Files produced by the Rust side

`cargo run --release -p provcheck-watermark --example decode_dump --
<audio-file>` writes two files next to the input:

```
<input>.rust.json   # metadata + binary offsets
<input>.rust.bin    # packed f32 + u8 arrays at those offsets
```

The JSON contains a `binary_offsets` map describing where each
array lives in the binary file, its dtype (`f32_le` or `u8`), and
its `count`.

## What the Python side needs to write

Two files, same shape, just with `.python.` in place of `.rust.`:

```
<input>.python.json
<input>.python.bin
```

The JSON's `binary_offsets` map must use the same keys as the
Rust dump. The diff tool reads each implementation's JSON for
offsets and seeks into its `.bin` to read the matching arrays.

## Keys + shapes (must match exactly)

All `f32_le` values are little-endian float32.

| key                  | dtype   | count                 | what it is |
|----------------------|---------|-----------------------|------------|
| `audio_pre_rescale`  | f32_le  | `n_samples`           | mono 44.1kHz f32 PCM samples, AFTER container decode, BEFORE VCTK rescale |
| `audio_post_rescale` | f32_le  | `n_samples`           | same samples, AFTER `y *= sqrt(VCTK / mean(y²))` |
| `carrier`            | f32_le  | `2049 * t_frames`     | STFT magnitudes, row-major [bin, t] → flat index `bin * T + t` |
| `logits`             | f32_le  | `5 * t_frames`        | decoder model output, row-major [dim, t] → flat index `dim * T + t` |
| `argmax`             | u8      | `t_frames`            | argmax of logits over the 5-axis per time frame |
| `mode_per_pos`       | u8      | `21`                  | per-tile-position mode across all `T // 21` tiles |
| `payload_symbols`    | u8      | `20`                  | mode_per_pos after cyclic-roll past terminator, with the encoder's +1 subtracted |
| `payload_bytes`      | u8      | `5`                   | 4 base-4 symbols MSB-first packed into each byte |

## Python implementation template

The Python reference decoder you already have presumably wraps
silentcipher's `decode_wav` or equivalent. Adapt to dump along
the way. The key invariants:

* `audio_pre_rescale` is the f32 mono 44.1kHz waveform that
  silentcipher's pipeline applies the VCTK rescale to. If
  silentcipher loads via librosa/soundfile, this is what's in
  memory just before the `y *= sqrt(...)` line.
* `carrier` is whatever the encoder passes to the decoder model —
  in stock silentcipher that's `STFT.transform(...)[0]`, which is
  magnitude (not log, not power, not phase).
* `logits` is the raw model output (no softmax).

Sketch:

```python
import json
import numpy as np
import struct
from pathlib import Path

# Load + decode + rescale.
y = your_load_to_mono_44k1(input_path)            # f32 array
mean_sq_pre = float(np.mean(y * y))
VCTK = 0.002837200844477648
y_post = y * float(np.sqrt(VCTK / mean_sq_pre))
mean_sq_post = float(np.mean(y_post * y_post))

# STFT (silentcipher's transform).
carrier = silentcipher_stft_transform(y_post)     # shape [2049, T] magnitude
T = carrier.shape[1]

# Model.
logits = silentcipher_model_run(carrier)          # shape [5, T]

# Argmax + mode + decode.
argmax = np.argmax(logits, axis=0).astype(np.uint8)         # [T]
n_tiles = T // 21
pred = argmax[: n_tiles * 21].reshape(n_tiles, 21)          # [n_tiles, 21]
mode_per_pos = np.array(                                    # [21]
    [int(np.bincount(pred[:, p], minlength=5).argmax()) for p in range(21)],
    dtype=np.uint8,
)
# Per-position mode tiebreaks at the smallest value — match numpy
# bincount + argmax default which does exactly that.

term_pos = np.where(mode_per_pos == 0)[0]
payload_symbols = np.zeros(20, dtype=np.uint8)
payload_bytes = np.zeros(5, dtype=np.uint8)
if len(term_pos) > 0:
    end_char = int(term_pos.min())
    rolled = np.concatenate(
        [mode_per_pos[end_char + 1 :], mode_per_pos[:end_char]]
    )
    if not np.any(rolled == 0):
        payload_symbols = (rolled - 1).astype(np.uint8)
        for b in range(5):
            a = payload_symbols[b * 4 + 0]
            c = payload_symbols[b * 4 + 1]
            d = payload_symbols[b * 4 + 2]
            e = payload_symbols[b * 4 + 3]
            payload_bytes[b] = (a << 6) | (c << 4) | (d << 2) | e

# Pack everything into a .bin file.
stem = Path(input_path).with_suffix("")
bin_path = stem.with_suffix(".python.bin")
json_path = stem.with_suffix(".python.json")
bin_fp = open(bin_path, "wb")
offsets = {}
def append(name, data, dtype):
    offsets[name] = {
        "offset": bin_fp.tell(),
        "dtype": dtype,
        "count": int(len(data) if dtype == "u8" else data.size),
    }
    if dtype == "f32_le":
        bin_fp.write(np.asarray(data, dtype=np.float32).tobytes())
    elif dtype == "u8":
        bin_fp.write(np.asarray(data, dtype=np.uint8).tobytes())
append("audio_pre_rescale", y, "f32_le")
append("audio_post_rescale", y_post, "f32_le")
append("carrier", carrier.flatten(order="C"), "f32_le")  # row-major [bin, T]
append("logits", logits.flatten(order="C"), "f32_le")    # row-major [5, T]
append("argmax", argmax, "u8")
append("mode_per_pos", mode_per_pos, "u8")
append("payload_symbols", payload_symbols, "u8")
append("payload_bytes", payload_bytes, "u8")
bin_fp.close()

json_path.write_text(json.dumps({
    "implementation": "silentcipher python reference",
    "input_path": str(input_path),
    "binary_dump_path": str(bin_path),
    "audio": {
        "n_samples": int(y.shape[0]),
        "sample_rate": 44100,
        "mean_sq_pre_rescale": mean_sq_pre,
        "mean_sq_post_rescale": mean_sq_post,
        "vctk_target_energy": VCTK,
    },
    "carrier": { "shape": [1, 1, 2049, T] },
    "logits":  { "shape": [1, 1, 5, T] },
    "binary_offsets": offsets,
}, indent=2))
```

## Running the diff

Once both implementations' dumps exist:

```bash
cargo run --release -p provcheck-watermark --example decode_diff -- \
    <input>.rust.json <input>.python.json
```

Output is one line per stage:

```
[STAGE 1: audio decode]
  audio_pre_rescale        n=  754560  L∞=2.3e-05  RMS=4.1e-06  tol=1e-05  DIFF
    first divergence at index 1024

[STAGE 2: VCTK rescale]
  audio_post_rescale       n=  754560  L∞=2.0e-05  RMS=3.6e-06  tol=1e-05  DIFF
...
```

The first `DIFF` line is the culprit stage. The `first divergence
at index` tells you exactly where in the array to look.

## Tolerances

Hand-tuned in `decode_diff.rs`:

* `TOL_AUDIO   = 1e-5` — post-decode samples differing by more than this means the MP3 decoder is the bug
* `TOL_CARRIER = 1e-3` — STFT round-off is ~`log2(N_FFT) * eps`, scaled by magnitude
* `TOL_LOGITS  = 1e-1` — neural-network accumulation; large but anything past this is real
