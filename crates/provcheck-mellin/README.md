# provcheck-mellin

Keyed spectral (Fourier-Mellin) forensic watermark channel: scale/stretch-invariant
embed and detect over i16 LE PCM. Ported from Lysn.fm's `lysn-watermark` crate
(`src/mellin.rs`) so the provenance suite can run seller-side forensic detection.

## This crate is opt-in, and it is NOT in the release binary

provcheck is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires everything
bundled into the binary to be permissively licensed. This crate is dual-licensed
**AGPL-3.0-or-later OR a commercial license** (see `LICENSE` and `LICENSING.md`),
which is copyleft, so it is excluded from the workspace, never wired into the
detector dispatch, and never shipped in the `.exe`. Build it standalone:

```
cargo build --manifest-path crates/provcheck-mellin/Cargo.toml
cargo test  --manifest-path crates/provcheck-mellin/Cargo.toml
```

## Why it is different from the other detector families

The other families (silentcipher, AudioSeal, WavMark, TrustMark, SynthID-text)
are *blind public detectors*: anyone can run them on any file. This channel is
**secret-keyed**: embedding and detection require the seller's secret and the
work id (`MellinChannel::for_work`), because it exists to individuate copies and
trace leaks, not to label AI output. It therefore does not fit the
`detect(path) -> WatermarkResult` dispatch, and it must never frame an innocent:
a low-confidence read returns an erasure (`None`), never a guessed bit.

## Reading and writing a serial from a file

On top of the channel, the crate carries a per-copy **serial** layer and a CLI
(`provcheck-mellin`) so a keyed 64-bit copy id can be written into and read back
from audio files. The serial is spread across `64 * repeat` positions with
majority-vote recovery, so a damaged copy erases rather than misreads:

```
cargo build --manifest-path crates/provcheck-mellin/Cargo.toml --release

# embed copy id 0xDEADBEEF into a 16-bit WAV
provcheck-mellin embed --secret <hex> --work-id my-work --serial deadbeef \
    --repeat 4 --strength 0.3 in.wav -o out.wav

# read it back from a leaked copy in ANY format (MP3, AAC, FLAC, ...)
provcheck-mellin read  --secret <hex> --work-id my-work \
    --repeat 8 --strength 0.35 --expect deadbeef leaked.mp3
```

Detection is keyed: without the seller secret and the work id there is no channel
key, so the serial does not read. `read` prints the recovered serial, how many of
the 64 bits were recovered, the erasure rate, and the weakest per-bit vote count;
`--expect` makes it exit 0 on a full match, 1 otherwise. The read side decodes any
format symphonia supports (WAV, MP3, AAC, FLAC, M4A, OGG), so a leak can be traced
whatever container it arrived in.

**Geometry and the vote budget.** Each position needs several FFT frames to clear
the detection gate, so keep roughly 2,560+ samples per position (embed warns
otherwise). A lossy transcode erases many positions, so each serial bit needs
several *surviving* repetitions to majority-vote correctly: watch the reported
"min bit votes". A thin budget (say `--repeat 4` on a short clip) can survive a
128 kbps MP3 but leaves single-vote bits that a codec can flip; music-length audio
at the `--repeat 8` default recovers cleanly through 128-192 kbps MP3/AAC with a
comfortable margin. Higher `--strength` is more robust but more audible, the usual
watermark trade-off.

**Stereo (and multi-channel).** Each channel is marked with the same keyed serial
and written back interleaved, so a stereo master stays stereo. On read the channels
are voted together, which multiplies the surviving-vote budget by the channel count,
so stereo is materially more robust through a lossy leak than mono at the same
settings. A mono input is simply the one-channel case.

**Scope:** WAV out (the lossless home format); any decodable format in. Only the
channel keys against Lysn.fm; the serial framing, decode, WAV write, and CLI are
provcheck-only.

## Collusion-resistant traitor tracing (Tardos)

The plain serial above individuates a copy, but a coalition of buyers who compare
copies can wash it out. `trace-embed` / `accuse` carry a **Tardos codeword**
instead: a per-buyer bit vector drawn from a secret per-work bias distribution,
spread one bit per position over the whole work. When several colluders average or
splice their copies, the marking assumption forces the shared bits through, and the
symmetric accusation score still names at least one real colluder while (the
guarantee held hardest) never framing an innocent.

```
# fingerprint one buyer's copy (positions = the Tardos code length)
provcheck-mellin trace-embed --secret <hex> --work-id album-9 --buyer alice \
    --positions 2500 --colluders 2 --strength 0.3 master.wav -o alice.wav

# trace a leak against the enrolled buyers (one label per line in buyers.txt)
provcheck-mellin accuse --secret <hex> --work-id album-9 \
    --positions 2500 --colluders 2 --fp-log10 4 --buyers buyers.txt leak.mp3
```

`accuse` derives each enrolled buyer's serial from `(secret, work_id, label)`,
scores every one against the detected symbols, and prints those above the
false-positive threshold, strongest first (exit 0 if any, 1 if none). It refuses to
accuse on fewer than 48 observed positions (below that the score is not yet normal,
so the bound would not hold, a miss preferred to a frame). The guarantees, validated
by the test suite rather than asserted:

- **No false accusation.** The run's false-positive probability is bounded by
  `10^-fp_log10` (Bonferroni-split over the enrolled population), independent of code
  length.
- **Soundness.** With enough positions at least one real colluder is named under
  every standard fusion attack (majority, minority, coin-flip, all-zero/one,
  interleave), even with channel bit-errors.

**Capacity scales with length.** A Tardos code needs on the order of
`50 * c^2 * ln(population / eps)` positions to resist `c` colluders, and each
position needs a couple of thousand audio samples, so collusion resistance is a
property of long-form content (albums, mixes, podcasts). `trace-embed` reports the
indicative capacity; short clips are capacity-limited and should lean on the plain
serial. Embed and accuse must pass the same `--positions` and `--colluders`.

## Compatibility contract with Lysn.fm

Two layers are bit-identical with `lysn-watermark`:

- the **channel** keying (HMAC label `lysn-mellin-key/v1`, the splitmix64-style
  PRNG, the keyed ±1 pattern), so a mark embedded by Lysn.fm reads here with the
  same seller secret and work id, and
- the **Tardos** math (labels `lysn-tardos/bias` and `lysn-tardos/codeword`, the
  bias distribution, the codeword rule, the symmetric score, the threshold, and
  the Acklam quantile), so a codeword scores identically given the same serial
  bytes and work seed.

Any change to a constant, label, or derivation in either must land in both repos
together. Everything else (the serial framing, the audio codeword mapping,
enrollment, WAV I/O, and the CLI) is provcheck-only and carries no such obligation.
