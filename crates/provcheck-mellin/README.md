# provcheck-mellin

Keyed spectral (Fourier-Mellin) forensic watermark channel: scale/stretch-invariant
embed and detect over i16 LE PCM. Ported from Lysn.fm's `lysn-watermark` crate
(`src/mellin.rs`) so the provenance suite can run seller-side forensic detection.

## This crate is opt-in, and it is NOT in the release binary

provcheck is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires everything
bundled into the binary to be permissively licensed. This crate is **BUSL-1.1**
(see `LICENSE`; it converts to Apache-2.0 on 2030-01-01), so it is excluded from
the workspace, never wired into the detector dispatch, and never shipped in the
`.exe`. Build it standalone:

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

**Scope:** WAV out (the lossless home format); any decodable format in.
Collusion-resistant traitor tracing (a Tardos codeword instead of a plain serial)
is the next layer. Only the channel keys against Lysn.fm; the serial framing,
decode, WAV write, and CLI are provcheck-only.

## Compatibility contract with Lysn.fm

The keying (HMAC label `lysn-mellin-key/v1`, the splitmix64-style PRNG, and the
keyed ±1 pattern) is bit-identical with `lysn-watermark`. Marks embedded by
Lysn.fm detect here with the same seller secret and work id, and vice versa. Any
change to a constant, label, or derivation must land in both repos together. The
serial framing, WAV I/O, and CLI above are provcheck-only and carry no such
obligation.
