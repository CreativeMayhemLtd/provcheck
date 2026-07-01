"""Differentiable AAC-approximation via Meta's Encodec.

Encodec (Meta FAIR, MIT-licensed) is a neural audio codec that
compresses audio into a discrete latent representation and reconstructs
it. Its reconstruction damage profile is similar to lossy audio codecs
(AAC, MP3, Opus) — it throws away perceptually-masked content and adds
quantisation artefacts. Using Encodec inside a differentiable training
loop lets an upstream encoder (e.g. silentcipher) learn to embed its
watermark in bands the codec preserves.

The trick that makes this work in a training loop where the codec's
discrete quantiser breaks gradient flow: **straight-through gradient
estimator**. Forward pass returns Encodec's output; backward pass
treats the codec as identity so gradients flow through. Standard
technique for training against discrete / non-differentiable ops.

Sample-rate handling: silentcipher operates at 44.1 kHz; Encodec's
default checkpoint is 24 kHz mono (or 48 kHz stereo for the 48k
variant). This module handles resampling both directions internally
via torchaudio, so the caller sees a 44.1 kHz waveform in and a
44.1 kHz waveform out.

Standalone reusability: import from any PyTorch pipeline as
    from codec_augmentation import EncodecAacAugmentation
Not tied to silentcipher; works for any waveform-in / waveform-out
augmentation position in a training loop.

License: MIT (this module). Depends on encodec (Meta, MIT) and
torchaudio (Meta, BSD). Compatible with any downstream MIT / Apache
license.
"""

from __future__ import annotations

from typing import Optional

import torch
import torch.nn as nn


# ---------------------------------------------------------------------------
# Bitrate → Encodec bandwidth mapping.
#
# Encodec's `set_target_bandwidth` takes a bandwidth in kbps. The
# available operating points depend on the specific Encodec checkpoint:
#     24 kHz mono model: 1.5, 3, 6, 12, 24 kbps
#     48 kHz stereo model: 3, 6, 12, 24 kbps
#
# AAC and Opus don't map 1:1 to Encodec's bandwidth ladder — a 192 kbps
# stereo AAC has a very different perceptual character than a 24 kbps
# Encodec stereo output. But Encodec's *distortion profile* (bands
# preserved vs discarded, quantisation noise shape) generalises well
# enough that training against Encodec produces marks that survive AAC
# at the same "roughly equivalent perceptual damage" bitrate.
#
# The mapping below was tuned against v0.5.2's codec-survival empirical
# findings: Encodec at 24 kbps ≈ AAC at ~192 kbps in preserved-band
# footprint. Adjust if empirical validation diverges.
# ---------------------------------------------------------------------------

_AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS = {
    320: 24.0,
    256: 24.0,
    192: 24.0,
    160: 12.0,
    128: 12.0,
    96: 6.0,
    64: 3.0,
    48: 3.0,
}


def _target_bandwidth_for_aac(aac_kbps: int) -> float:
    """Pick the Encodec bandwidth that best approximates AAC at kbps."""
    if aac_kbps in _AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS:
        return _AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS[aac_kbps]
    # Fall through: pick the highest AAC bitrate we know that is
    # ≤ requested. Callers requesting 224 get the 192 setting.
    for kbps in sorted(_AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS, reverse=True):
        if kbps <= aac_kbps:
            return _AAC_BITRATE_TO_ENCODEC_BANDWIDTH_KBPS[kbps]
    # Requested bitrate is below anything we've profiled. Fall back to
    # the lowest Encodec setting.
    return 3.0


# ---------------------------------------------------------------------------
# The augmentation module.
# ---------------------------------------------------------------------------


class EncodecAacAugmentation(nn.Module):
    """Differentiable AAC approximation via Meta's Encodec + straight-through gradient.

    Usage:
        aug = EncodecAacAugmentation(target_bitrate_kbps=192).cuda()

        # In your training loop:
        #   waveform shape: [B, C, T] where C in {1, 2} and T is samples
        #   at self.input_sample_rate (default 44100).
        encoded = aug(waveform)   # same shape, differentiable

    The forward pass:
        1. Resample from self.input_sample_rate → self.encodec_sample_rate.
        2. Encode with Encodec.
        3. Decode with Encodec.
        4. Resample back → self.input_sample_rate.
        5. Apply straight-through gradient: output = x + (encoded - x).detach()
           So the forward output IS the encoded waveform, but gradients
           w.r.t. x pass through as identity.

    The straight-through wrapper is the key trick. Without it, the
    non-differentiable Encodec quantiser would block gradient flow
    from the training loss back to the upstream encoder we're trying
    to fine-tune. With it, the encoder learns which frequency bands
    the codec preserves without needing a differentiable codec.

    Args:
        target_bitrate_kbps: The AAC bitrate we're training to survive.
            Maps to an Encodec bandwidth via the profiled table.
            Common: 192 (default AAC streaming), 128 (aggressive), 96
            (very aggressive; edge of feasibility).
        input_sample_rate: Sample rate of the caller's waveforms.
            Default 44100 (matches silentcipher). Set to 48000 for
            video-audio pipelines; 16000 for speech-first pipelines.
        encodec_variant: Which Encodec checkpoint to use.
            "24khz" (default): mono, 24 kHz, more bandwidth options
            "48khz": stereo, 48 kHz, better for music applications
        stochastic: If True, randomise the target bitrate each forward
            pass across the profiled bitrates in [96, 128, 192, 256].
            Encourages robustness across a range of delivery codecs
            rather than one specific setting.
    """

    def __init__(
        self,
        target_bitrate_kbps: int = 192,
        input_sample_rate: int = 44100,
        encodec_variant: str = "24khz",
        stochastic: bool = False,
    ) -> None:
        super().__init__()
        self.target_bitrate_kbps = int(target_bitrate_kbps)
        self.input_sample_rate = int(input_sample_rate)
        self.encodec_variant = encodec_variant
        self.stochastic = bool(stochastic)

        # Lazy-import encodec so that unrelated imports of this module
        # (e.g. from a test harness that never calls forward) do not
        # incur the Encodec model download / import cost.
        from encodec import EncodecModel

        if encodec_variant == "24khz":
            self.encodec = EncodecModel.encodec_model_24khz()
            self.encodec_sample_rate = 24000
        elif encodec_variant == "48khz":
            self.encodec = EncodecModel.encodec_model_48khz()
            self.encodec_sample_rate = 48000
        else:
            raise ValueError(
                f"encodec_variant must be '24khz' or '48khz'; got "
                f"{encodec_variant!r}"
            )

        # Set the initial bandwidth. In stochastic mode we override
        # this per forward pass.
        self.encodec.set_target_bandwidth(
            _target_bandwidth_for_aac(self.target_bitrate_kbps)
        )

        # Encodec is inference-only in a training loop — its weights
        # stay frozen. We don't backprop through Encodec's parameters;
        # only through the straight-through wrapper.
        for p in self.encodec.parameters():
            p.requires_grad_(False)
        self.encodec.eval()

        # Resamplers. Cached at construction so we don't rebuild them
        # every forward. torchaudio's Resample is a subclass of nn.Module
        # so it moves to the correct device via .cuda()/.to().
        import torchaudio.transforms as T

        if self.input_sample_rate != self.encodec_sample_rate:
            self._resample_down = T.Resample(
                orig_freq=self.input_sample_rate,
                new_freq=self.encodec_sample_rate,
            )
            self._resample_up = T.Resample(
                orig_freq=self.encodec_sample_rate,
                new_freq=self.input_sample_rate,
            )
        else:
            self._resample_down = nn.Identity()
            self._resample_up = nn.Identity()

    # ------------------------------------------------------------------
    # forward
    # ------------------------------------------------------------------

    def forward(self, waveform: torch.Tensor) -> torch.Tensor:
        """Apply the codec augmentation.

        Args:
            waveform: shape [B, C, T] float32, in [-1, 1].
                B = batch size
                C = channels (1 for mono, 2 for stereo)
                T = samples at self.input_sample_rate

        Returns:
            Same shape as input; codec-degraded but differentiable w.r.t.
            input via straight-through gradient.
        """
        if waveform.dim() != 3:
            raise ValueError(
                f"expected waveform shape [B, C, T]; got {waveform.shape}"
            )

        # Optional stochastic bitrate: randomise per forward pass to
        # train against a range of codec settings rather than a single
        # target. Improves robustness across delivery pipelines.
        if self.stochastic and self.training:
            import random

            bitrate = random.choice([96, 128, 192, 256])
            self.encodec.set_target_bandwidth(
                _target_bandwidth_for_aac(bitrate)
            )

        # 1. Resample down to Encodec's native sample rate.
        w_down = self._resample_down(waveform)

        # 2. Encode + decode. Encodec expects [B, C, T].
        # We disable gradients here — Encodec's params stay frozen and
        # we don't want the graph to include Encodec's internals. The
        # straight-through wrapper below is what carries the gradient.
        with torch.no_grad():
            encoded_frames = self.encodec.encode(w_down)
            decoded = self.encodec.decode(encoded_frames)

        # 3. Resample back up.
        w_up = self._resample_up(decoded)

        # Trim / pad to match input length. Resampling can add or drop a
        # few samples depending on the rate ratio.
        target_len = waveform.shape[-1]
        cur_len = w_up.shape[-1]
        if cur_len > target_len:
            w_up = w_up[..., :target_len]
        elif cur_len < target_len:
            pad = target_len - cur_len
            w_up = torch.nn.functional.pad(w_up, (0, pad))

        # 4. Straight-through gradient: forward is w_up (codec output),
        # backward gradient is identity through waveform.
        return waveform + (w_up - waveform).detach()

    # ------------------------------------------------------------------
    # Convenience: set bitrate at run-time
    # ------------------------------------------------------------------

    def set_target_bitrate(self, aac_kbps: int) -> None:
        """Change the AAC bitrate target without rebuilding the module."""
        self.target_bitrate_kbps = int(aac_kbps)
        self.encodec.set_target_bandwidth(
            _target_bandwidth_for_aac(self.target_bitrate_kbps)
        )
