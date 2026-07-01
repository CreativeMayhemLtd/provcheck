"""Differentiable audio-codec augmentations for training-time robustness.

Standalone module — importable in any PyTorch training pipeline, not
tied to silentcipher. Reuse across watermarking / speech / music
generation projects.

Public API:
    from codec_augmentation import EncodecAacAugmentation

    aug = EncodecAacAugmentation(target_bitrate_kbps=192)
    aug = aug.cuda()

    # Inside your training loop:
    encoded_audio = aug(waveform)   # differentiable

Straight-through gradient: forward pass returns the codec-degraded
waveform; backward pass treats the codec as an identity function so
gradients flow through to the encoder. This is the standard trick
for training against discrete / non-differentiable operations.

Two augmentations ship:
    - EncodecAacAugmentation (Option A, primary) — uses Meta's Encodec
      as a differentiable proxy for AAC's psychoacoustic damage
    - PsychoacousticAugmentation (Option B, fallback) — static bark-
      band mask + additive quantisation noise; lighter and always
      available even if Encodec integration fails

Both share the same __call__ signature:  aug(waveform) -> waveform
"""

from .encodec_aac import EncodecAacAugmentation

__all__ = ["EncodecAacAugmentation"]

# Option B (psychoacoustic fallback) lands in a follow-up commit if
# Option A hits an integration wall. Not exported here yet; import
# from .psychoacoustic directly when it exists.
