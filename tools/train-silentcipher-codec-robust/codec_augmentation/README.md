# codec_augmentation — differentiable audio-codec augmentations

Standalone module of differentiable audio-codec augmentations for training-time robustness. Importable in any PyTorch pipeline. Not tied to silentcipher; sits inside the silentcipher fine-tune scaffold today but designed for reuse across watermarking, speech generation, music generation, or any training where "make the model robust to lossy codec X" is a goal.

## License

MIT (Creative Mayhem UG). Depends on:
- `encodec` (Meta FAIR, MIT)
- `torchaudio` (Meta, BSD)
- `torch` (Meta, BSD)

Compatible with any downstream MIT / Apache / BSD project.

## Quick start

```python
from codec_augmentation import EncodecAacAugmentation

# Instantiate the augmentation once (loads Encodec's frozen weights).
aug = EncodecAacAugmentation(
    target_bitrate_kbps=192,
    input_sample_rate=44100,
    encodec_variant="24khz",
    stochastic=False,
).cuda()

# In your training loop:
for waveform, target in dataloader:
    waveform = waveform.cuda()  # shape [B, C, T] in [-1, 1]

    # Apply the codec augmentation somewhere in your forward pass.
    # For a watermarking model, this typically sits between the encoder's
    # output and the decoder's input:
    #     x -> encoder -> waveform_with_mark -> aug -> decoder -> payload
    codec_degraded = aug(waveform_with_mark)

    # Continue training as normal. Gradients flow through aug via
    # straight-through estimator.
    payload_pred = decoder(codec_degraded)
    loss = bce(payload_pred, target)
    loss.backward()
    optimizer.step()
```

## How it works

Meta's Encodec is a neural audio codec that operates on discrete latents. Its reconstruction damage profile is similar to lossy audio codecs (AAC, MP3, Opus) — the "keep mask" of preserved frequency content resembles what psychoacoustic codecs decide is important. Training an upstream encoder against Encodec's damage teaches the encoder to hide the watermark in the same bands the delivery codec will preserve.

The key trick is the **straight-through gradient estimator**. Encodec's quantiser is non-differentiable, which would break gradient flow. The forward pass returns `x + (encoded - x).detach()`, which numerically equals `encoded` (the codec output) but has an identity gradient w.r.t. `x`. So the training loss's gradient flows through the augmentation as if it were an identity function, teaching the upstream encoder to place its signal where the codec preserves it.

## API

### `EncodecAacAugmentation(target_bitrate_kbps=192, input_sample_rate=44100, encodec_variant="24khz", stochastic=False)`

Applies a differentiable AAC-approximation via Encodec.

- `target_bitrate_kbps`: AAC bitrate to train robustness against. Mapped to an Encodec bandwidth via the profiled table (`_AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS`). Common values: 192 (streaming default), 128 (aggressive), 96 (edge of feasibility).
- `input_sample_rate`: Sample rate of the caller's waveforms. Default 44100 (silentcipher). Set to 48000 for video-audio, 16000 for speech-first.
- `encodec_variant`: `"24khz"` (mono) or `"48khz"` (stereo). Choose based on your input channel count.
- `stochastic`: If True, randomises the bitrate each forward pass across the profiled range. Trains against a range of delivery codecs rather than one specific setting.

Forward pass:

```python
codec_degraded = aug(waveform)   # shape [B, C, T], differentiable
```

### `.set_target_bitrate(aac_kbps)`

Change the AAC bitrate target without rebuilding the module. Useful for curriculum-style training that starts at 192 kbps and ramps to 128 kbps over training.

## Bitrate mapping

Encodec's bandwidth options don't 1:1 map to AAC bitrates, but the *distortion profile* generalises well enough that training against Encodec at a well-chosen bandwidth produces marks that survive AAC at a specific target. The profiled mapping (see `_AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS` in `encodec_aac.py`):

| AAC target | Encodec bandwidth |
|---|---|
| 320 kbps | 24 kbps (max) |
| 256 kbps | 24 kbps |
| 192 kbps | 24 kbps |
| 160 kbps | 12 kbps |
| 128 kbps | 12 kbps |
| 96 kbps | 6 kbps |
| 64 kbps | 3 kbps |
| 48 kbps | 3 kbps (min) |

This mapping was tuned against provcheck's v0.5.2 codec-survival empirical findings (Encodec at 24 kbps ≈ AAC at 192 kbps in preserved-band footprint). Adjust if empirical validation diverges from your target codec.

## Reusability notes

This module lives inside the silentcipher fine-tune scaffold today but is intentionally decoupled from any silentcipher-specific code. For reuse in another training pipeline:

1. Copy `codec_augmentation/` into your project (or add this tools/ subtree as a git submodule).
2. Install `torch`, `torchaudio`, `encodec` in your environment.
3. Instantiate `EncodecAacAugmentation` with the sample rate + channel count matching your inputs.
4. Drop into your training loop between the layer you want to train against codec attacks and the loss.

## Follow-up

- Option B augmentation (`psychoacoustic.py`) — static bark-band mask + quantisation noise fallback if Encodec integration lands hard in some environment. Not landed here yet.
- Opus-specific approximation via `libopus` bindings — could ship as `EncodecOpusAugmentation` sibling if silentcipher's Opus survival becomes a target.
- Multi-codec cycling — chain multiple codecs per forward pass (AAC → Opus → MP3) to train against the worst-case delivery-pipeline abuse. Trivial extension.
