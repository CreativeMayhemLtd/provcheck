# Watermark codec survival — v0.5.2 investigation

This directory is both:

1. The **investigation record** for public issue #23, where the v0.5.1
   silentcipher embed produced marks that failed to survive any lossy
   re-encode.
2. The **regression harness** for any future change that could reopen
   the parity gap against upstream Python silentcipher. The parity
   script lives at
   [`scripts/parity-vs-upstream.py`](../../scripts/parity-vs-upstream.py)
   and can be re-run with one command.

## TL;DR

- The v0.5.1 chunking refactor (public issue #17) is NOT the cause of
  the regression. Sample-by-sample correlation between our Rust embed
  output and upstream Python silentcipher's embed output is **1.000
  across every tested SDR**. The Rust port is numerically faithful.
- The 47 dB training default is far above the survivability margin
  for any lossy codec. **At 30 dB it works for MP3 and (post-v0.5.3)
  for AAC.**
- **MP3 (libmp3lame) delivery survives the embed.** Rust embed at SDR
  30 dB into MP3 192k retains conf 0.95 (well above the 0.85
  robustness threshold).
- v0.5.2 lowers `DEFAULT_MESSAGE_SDR_DB` from 47 to 30, adds stereo
  embed (two independent mono embeds with the same payload), and
  always-on verify-after-embed self-test.

## v0.5.3 correction — silentcipher AAC delivery actually works

The first version of this doc concluded that "AAC delivery does NOT
survive the embed under any tested combination" of bitrate, SDR,
channel count, or implementation. **That conclusion was wrong.**
Public issue #24 surfaced the real root cause: the silentcipher
*embed* always survived AAC at conf 0.92, but the *detector* was
silently returning conf 0.000 on AAC-in-MP4/M4A because symphonia
0.5.5 does not surface the MP4 `edts/elst` or `iTunSMPB` priming
metadata as `codec_params.delay`. So our decode left every STFT
frame 1024 samples out of phase with the embedder's frame grid.

v0.5.3 fixes this by hardcoding `AAC_DEFAULT_PRIMING_SAMPLES = 1024`
when symphonia returns `delay = None` for an AAC track. The fix
also adds `mp4`, `m4b`, and `mov` to the audio-extension allowlist
(MP4 video containers with an AAC audio track previously got
rejected by the early `looks_like_audio` sniff).

Post-fix numbers on the same 15-second segment, Rust embed at SDR
30 dB ➝ ffmpeg aac 192k stereo ➝ Rust detector:

| Container | Pre-fix conf | Post-fix conf |
|---|---:|---:|
| `.m4a` (AAC in MP4 audio container) | 0.000 | 0.921 |
| `.mp4` (AAC alongside h264 video) | 0.000 | 0.921 |

Independent verification: ffmpeg-decoding the same AAC bitstream to
PCM and detecting that PCM gives conf 0.921 — confirming the mark
was always there; the only thing wrong was our decoder's frame
alignment. AudioSeal stays the recommended path for AAC delivery
(higher post-AAC margin, see below) but silentcipher is now a
viable second option for pipelines that prefer the 40-bit ASCII
payload.

## Findings table

15-second segment of `examples/rAIdio.bot-sample.mp3` (44.1 kHz mono,
DFM payload), default LAME ffmpeg encoders, Rust detector.

### Pristine PCM (parity gap analysis)

| SDR (dB) | Py-embed → Py-detect | Py-embed → Rust-detect | Rust-embed → Py-detect | Rust-embed → Rust-detect |
|---:|---:|---:|---:|---:|
| 25 | 0.984 | 0.902 | 0.965 | 0.927 |
| 30 | 0.990 | 0.933 | 0.968 | 0.959 |
| 35 | 0.997 | 0.959 | 0.971 | 0.981 |
| 40 | 0.997 | 0.956 | 0.940 | 0.987 |
| 47 | 0.949 | 0.000 | 0.857 | 0.908 |

**Sample-by-sample correlation Py-Rust at every SDR: 1.000.**

Each implementation prefers its own embed by ~2-3 confidence points
across the working range. The Rust-detect-on-Python-embed cliff at SDR
47 (0.000) is a separate detector sensitivity bug worth a v0.5.3
followup; it does not affect the v0.5.2 ship because the kit-only
self-loop is robust.

### Re-encode survival (Rust detector on the re-encoded output)

| SDR (dB) | Rust pristine | Rust → MP3 192k mono | Rust → AAC 192k stereo |
|---:|---:|---:|---:|
| 25 | 0.927 | 0.930 | 0.000 |
| 30 | 0.959 | 0.952 | 0.000 |
| 35 | 0.981 | 0.965 | 0.000 |
| 40 | 0.987 | 0.975 | 0.000 |
| 47 | 0.908 | 0.895 | 0.000 |

AAC was also tested at 256k stereo, 320k stereo, and `-q:a 5` VBR;
all returned conf 0.000.

## AudioSeal — the AAC answer

Same 15-second segment, AudioSeal embed via the existing
`--kind audioseal` path, alpha sweep:

| alpha | pristine | AAC 192k stereo | MP3 192k mono | brand recovery |
|---:|---:|---:|---:|---|
| 1.0 (upstream default) | 0.671 | 0.369 | 0.689 | borderline (conf below detected threshold) |
| 3.0 | 0.999 | 0.999 | 0.999 | clean on PCM and MP3, brand_id bit-flip on AAC |
| 5.0 | 0.998 | 0.999 | 0.999 | clean across all three |

AudioSeal alpha=1.0 (the upstream README's default) produces a
mark that sits below our 0.70 detected threshold even on pristine
PCM. v0.5.2 raises the AudioSeal default alpha to 3.0 so the
default behaviour reliably detects and survives AAC delivery.
v0.5.2 also documents alpha 5.0 for pipelines that need clean
brand-ID recovery through AAC.

## Conclusions

1. **silentcipher default SDR drops from 47 dB to 30 dB.** Survives
   MP3 192k at conf 0.95 with comfortable margin. Pristine
   self-detect at 0.96. AAC delivery for silentcipher remains
   architecturally unsupported.
2. **AudioSeal default alpha rises from 1.0 to 3.0.** Survives both
   AAC 192k and MP3 192k at conf 0.999. AudioSeal is the
   recommended path for AAC delivery pipelines.
3. **Stereo embed** (orchestrating two mono embeds with the same
   payload) is mandatory for stereo delivery pipelines, since
   downmix-then-upmix breaks the mark and most delivery formats are
   stereo. Both silentcipher and AudioSeal get stereo entry points.
   The detector accepts stereo input by downmixing to mono first,
   so a stereo marked file detects on either single channel or on
   the mono mix.
4. **AudioSeal payload bit-flip through AAC at alpha=3.0 is a
   followup**. ECC redundancy survives high-confidence detection
   but a single bit-flip can land on a brand_id boundary. Either
   bump default alpha higher or add a brand-ID consistency check
   that votes across multiple decoded payloads from the same
   stream. Tracked as a v0.5.3 followup.

## Re-running the harness

```sh
# Install upstream silentcipher and download the 44.1k weights:
pip install silentcipher librosa soundfile numpy
python -c "from huggingface_hub import snapshot_download; snapshot_download('sony/silentcipher')"

# Build the release CLI:
cargo build --release --bin provcheck-kit --bin provcheck

# Run the sweep:
python scripts/parity-vs-upstream.py examples/rAIdio.bot-sample.mp3 --duration-s 15
```

Outputs and intermediate WAVs land in `target/parity-vs-upstream/`.
Pass `--skip-codec` to skip the AAC + MP3 re-encode pass if ffmpeg is
not available.

## Notes on the reporter's v2 reference

Public issue #23 references an earlier in-house pipeline whose marks
allegedly survived libmp3lame 192k at conf 0.98 and AAC at conf 0.99.
The MP3 number is now reproducible with our Rust embed at SDR 30 dB
(conf 0.95) once the default is lowered. The AAC number cannot be
reproduced with silentcipher under any tested encoder configuration;
that pipeline likely used a different watermark family or a different
AAC encoder (libfdk_aac, qaac) than the libavcodec built-in tested
here. v0.5.2 does not attempt to match the AAC claim; it documents
the silentcipher limit honestly.
