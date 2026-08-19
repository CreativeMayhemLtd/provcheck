# provcheck-mellin robustness

An honest, measured statement of what the Fourier-Mellin forensic channel
survives and what it does not. Companion to the provcheck FOSS survival docs,
kept here because this crate is the AGPL-or-commercial layer, not part of the
Apache-2.0 detection suite.

## The provenance-stripping toolkit is the wrong adversary

The public provenance-stripping tool measured in
[`docs/provenance-stripping-survival.md`](../../docs/provenance-stripping-survival.md)
(watermarks-remover) targets **text, image, and file-metadata** provenance. This
channel is an **audio** watermark living in the PCM magnitude spectrum. Run
against a mellin-marked WAV, the tool refuses the file outright ("bytes match no
supported text, image or container format") and produces no output, so the mark
is untouched. That is a true result but a vacuous one: the adversary has no audio
capability and cannot engage. The meaningful adversaries for an audio watermark
are audio-domain signal processing, measured below.

## Audio-domain survival sweep

Measured 2026-08-16 with `scripts/adversarial-sweep.sh`: a known serial embedded
into 60 s of broadband audio at `--repeat 8 --strength 0.35` (mono), each attack
applied with ffmpeg, then read back. Legend: ✓ survives (full serial recovered);
✗ does not survive (and the read reports it, never a wrong serial).

| Attack | Survives | Notes |
|---|---|---|
| Clean WAV / FLAC (lossless) | ✓ | full margin (8 votes/bit) |
| MP3 320 / 192 / 128 / 96 kbps | ✓ | recovered at every bitrate down to 96k |
| AAC 128 / 96 kbps | ✓ | recovered; margin thins at 96k |
| **Time-stretch (WSOLA / atempo) ±5%, +10%** | ✓ | the Fourier-Mellin design target: a magnitude-domain, frame-averaged mark is time-warp invariant where a time-domain chip is destroyed |
| **Resample / speed change ±3%** | ✓ | caught by the detector's ±4% frequency-scale search |
| Low-pass 6 kHz / 4 kHz | ✓ | the mark's mid-band (roughly 1.1 to 8.4 kHz) survives partial high-cut |
| Volume ±6 dB (linear gain) | ✓ | magnitude-domain detection is gain-relative |
| Opus 128 / 96 kbps | ✗ | Opus resamples to 48 kHz and applies aggressive psychoacoustic shaping; destroys the mark (same boundary silentcipher hits) |
| Resample / speed change ±6% | ✗ | beyond the ±4% frequency-scale search grid |
| Loudness normalization (EBU R128 `loudnorm`) | ✗ | nonlinear multiband compression, unlike a linear gain change |
| Trim / crop (5 s to 55 s) | ✗ | detection splits the whole stream proportionally into positions, so a crop shifts the alignment; resync on a trimmed clip is not yet implemented |

Margin scales with the settings: a higher `--strength`, a higher `--repeat`, and
stereo (both channels voted together) all deepen the surviving-vote budget, so the
marginal codec rows above move well clear of the threshold on real stereo,
music-length content.

## Collusion (the attack Tardos is built for)

Separately measured end to end (see `tardos.rs` / `trace.rs`): two buyers who
**averaged their marked copies** to wash the fingerprint were **both named** by
the accusation stage, with no innocent framed, and a single buyer traced from
their own copy and through a 128 kbps MP3. Collusion resistance scales with the
Tardos code length, i.e. with audio duration (see the README capacity note).

## Honest boundaries

1. **Opus and heavy nonlinear processing** (loudnorm, aggressive multiband
   dynamics) can strip the mark. Deliver marked masters as WAV/FLAC/MP3/AAC.
2. **Large speed changes (> ~4%)** fall outside the frequency-scale search grid.
3. **Cropping a clip** breaks the proportional position alignment; whole-work
   leaks trace, trimmed excerpts do not (yet).
4. These are channel-level constants shared bit-for-bit with lysn-watermark;
   widening the search grid or adding trim-resync is a coordinated cross-repo
   change, not a local tweak.
