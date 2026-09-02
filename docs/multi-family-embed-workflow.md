# Multi-family embed workflow

Operators embedding all three shipped audio watermark families (silentcipher / AudioSeal / WavMark) on the same source audio get the **union of survival envelopes**. This document is the operator-side workflow for the multi-family embed and the verifier-side story that lights it up.

## Why multi-family embed

Each detector family survives a different attack profile. Details in [`audio-watermark-survival-range.md`](./audio-watermark-survival-range.md). Composite result:

| Attack | Recovered by |
|---|---|
| Lossless / MP3 320 | silentcipher + AudioSeal + WavMark |
| MP3 192 | silentcipher + AudioSeal + WavMark |
| AAC 192 / AAC 320 | AudioSeal + WavMark |
| MP3 128 / AAC 128 | AudioSeal + WavMark |
| AAC 96 / Opus 64 | AudioSeal |
| Tempo / pitch change ±5% | AudioSeal (partial) |
| Loudness normalisation ±6 dB | all three |
| Speaker → mic re-recording (clean) | AudioSeal (partial) |

Adversary has to defeat every family the operator embedded to strip provenance.

## The workflow

```bash
# Step 1 — silentcipher first (highest capacity: 40 bits, brand + episode + timestamp).
# --channels auto preserves the source channel layout; verify-after-embed
# is on by default and refuses to write a weak-mark output.
provcheck-kit watermark input.wav \
    -o step1_silentcipher.wav \
    --kind silentcipher \
    --payload 44464d0100 \
    --channels auto

# Step 2 — AudioSeal on the silentcipher-marked output.
# Payload is a 5-bit brand ID (matches your atproto-published brand
# registration). Alpha 3.0 is the AAC-survivable default from v0.5.2.
provcheck-kit watermark step1_silentcipher.wav \
    -o step2_silentcipher_audioseal.wav \
    --kind audioseal \
    --brand-id 1 \
    --alpha 3.0 \
    --channels auto

# Step 3 — WavMark on the doubly-marked output.
# 32-bit payload: upper 16 bits reserved, lower 16 hold the brand ID
# (same encoding as AudioSeal).
provcheck-kit watermark step2_silentcipher_audioseal.wav \
    -o step3_all_three.wav \
    --kind wavmark \
    --brand-id 1 \
    --channels auto

# (Optional) Step 4 — sign the final artefact with C2PA + atproto identity.
provcheck-kit stamp step3_all_three.wav \
    -o final.wav \
    --brand-id 1

# The final.wav carries all three watermarks + a C2PA manifest signed
# with the operator's atproto-anchored identity.
```

## Verifier-side story

The verifier runs every registered detector on the input:

```bash
provcheck final.wav
```

Reports:

```
[VERIFIED]
  manifest: urn:c2pa:...
  signer: <brand>
  attested by: @<operator>.bsky.social
[watermarks]
  silentcipher: detected — <brand> (94% confidence)
    payload: 44464d0100
  audioseal:    detected — <brand> (91% confidence)
  wavmark:      detected — <brand> (89% confidence)
[assertions]
  c2pa.actions.v2 = {...}
  com.<brand>.<label> = {...}
```

If the file was re-encoded through AAC 192 kbps between publish and verify, the report might read:

```
[VERIFIED]  (or [UNSIGNED] if C2PA manifest stripped by re-encode)
[watermarks]
  silentcipher: not detected (dropped by the AAC re-encode)
  audioseal:    detected — <brand> (93% confidence)
  wavmark:      detected — <brand> (87% confidence)
```

Provenance intact even if the cryptographic layer got stripped by the container re-encode.

## Cost trade-offs

**Time cost**: three sequential embeds, dominated by the silentcipher pass. At v0.6.0's chunk-parallel silentcipher throughput on CPU (about 0.7x realtime), silentcipher on a 30-minute episode is roughly 20 minutes of wall-clock, and AudioSeal and WavMark add only seconds-to-tens-of-seconds each. GPU-accelerated silentcipher embed (about 10x faster) drops the silentcipher pass to a couple of minutes on the same episode.

**Audibility cost**: cumulative alpha across all three embeds adds ~0.5–1.0 dB to the audibility floor. Still inaudible under normal listening conditions. If audibility is a critical constraint (mastered music at reference volume through studio monitors), consider embedding only silentcipher + one of AudioSeal / WavMark. Two of three still gets you significant redundancy.

**Storage cost**: none beyond the source. Each embed produces a same-size WAV; only the final output is retained by pipelines that pipe steps 1 and 2 into ephemeral temp dirs.

## When multi-family is overkill

For low-audibility masters (studio music, mastered advertising) where a single family is sufficient because the delivery pipeline is known:

| Delivery pipeline | Single-family choice |
|---|---|
| Lossless / MP3 320 delivery only | silentcipher (highest payload capacity + best imperceptibility) |
| AAC 192 kbps streaming (YouTube / Spotify / Apple Music) | AudioSeal alpha=3.0 |
| Podcast delivery (MP3 128–192 kbps stereo) | silentcipher at SDR 30 dB (v0.5.2 default) |
| Voice content that may be re-recorded through room mics | AudioSeal alpha=3.0 |

For the general case where the delivery pipeline is unknown or diverse (public web release, redistributor pipelines, adversarial republishing), **multi-family embed is the safe default**.

## When multi-family isn't enough

The multi-family stack does not defeat every attack. Marks may drop under:

- AAC or Opus below 128 kbps
- Tempo or pitch changes >5%
- Heavy reverb, distant mic re-recording, or noisy acoustic capture
- Chopped-and-reordered DJ remixes with pitch shift + tempo change + effects
- Speech codecs (Speex, AMR, GSM)

For those scenarios, the honest answer today is that no shipped watermark technology recovers reliably. This is active research territory. See [`audio-watermark-survival-range.md`](./audio-watermark-survival-range.md) for the full table.

## Reference

- [`audio-watermark-survival-range.md`](./audio-watermark-survival-range.md) — per-attack, per-family table
- [`brand-registry.md`](./brand-registry.md) — 5-bit brand ID numeric registry
- [`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md) — the license policy every family passes
