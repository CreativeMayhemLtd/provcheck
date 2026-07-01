#!/usr/bin/env python3
"""Main training loop for the silentcipher codec-robust fine-tune.

Usage:
    python train.py --config configs/night1.yaml   # first night
    python train.py --config configs/night2.yaml   # continuation

Runs the encoder-only fine-tune with Encodec-based codec augmentation.
Guards for OOM, disk, safe-stop signal, and graceful SIGTERM. Writes
checkpoints + logs to the deliverable directory specified in the
config (default `C:/local_dev_tmp/silentcipher-codec-robust`).

Design contract with the rest of the scaffold:
    - Config YAML is the single source of truth. No argparse overrides
      other than --config.
    - Every 30 min: checkpoint + disk-check.
    - Every step: log to train.log; every 100 steps emit a metrics row.
    - Safe-stop: touch <repo-root>/stop.flag → next step exits cleanly.
    - OOM: caught, batch halved, retried. Never crashes on VRAM pressure.

Model-adaptation points (marked SILENTCIPHER_API_TODO) are the four
places where Sony's silentcipher package API gets called. If Sony's
package version changes those signatures, only these four sites need
adjustment. Rest of the loop is model-agnostic.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchaudio
import yaml

# Local module (codec_augmentation/ sibling directory).
sys.path.insert(0, str(Path(__file__).parent))
from codec_augmentation import EncodecAacAugmentation  # noqa: E402


# ============================================================================
# Terminal / logging helpers
# ============================================================================


def red(msg: str) -> None:
    print(f"\033[31m{msg}\033[0m", file=sys.stderr)


def yellow(msg: str) -> None:
    print(f"\033[33m{msg}\033[0m")


def green(msg: str) -> None:
    print(f"\033[32m{msg}\033[0m")


def log(msg: str, *, log_file: Optional[Path] = None) -> None:
    """Print to stdout AND append to train.log."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line)
    if log_file:
        with log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


# ============================================================================
# Config loading
# ============================================================================


@dataclass
class Config:
    run_name: str
    seed: int
    total_steps: int
    wallclock_ceiling_hours: float
    batch_size: int
    clip_seconds: float
    sample_rate: int
    channels: int
    base_checkpoint: Optional[str]
    freeze_decoder: bool
    aug_option: str
    aug_target_bitrate_kbps: int
    aug_straight_through: bool
    recon_l1_weight: float
    recon_mel_weight: float
    msg_bce_weight_start: float
    msg_bce_weight_end: float
    msg_bce_ramp_steps: int
    lr: float
    weight_decay: float
    gradient_clip: float
    ckpt_interval_seconds: int
    ckpt_keep_last_n: int
    ckpt_keep_best: bool
    step_log_interval: int
    disk_check_interval_seconds: int
    stop_flag_path: Path
    oom_retry: bool
    deliverable_dir: Path
    train_corpus: str
    augmentation_corpus: Optional[str]
    augmentation_weight: float


def load_config(path: Path) -> Config:
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    tool_dir = path.parent.parent  # configs/ → tool_dir
    return Config(
        run_name=raw["run"]["name"],
        seed=int(raw["run"]["seed"]),
        total_steps=int(raw["run"]["total_steps"]),
        wallclock_ceiling_hours=float(raw["run"]["wallclock_ceiling_hours"]),
        batch_size=int(raw["data"]["batch_size"]),
        clip_seconds=float(raw["data"]["clip_seconds"]),
        sample_rate=int(raw["data"]["sample_rate"]),
        channels=int(raw["data"]["channels"]),
        base_checkpoint=raw["model"]["base_checkpoint"],
        freeze_decoder=bool(raw["model"]["freeze_decoder"]),
        aug_option=raw["augmentation"]["option"],
        aug_target_bitrate_kbps=int(
            raw["augmentation"]["encodec"]["target_bitrate_kbps"]
        ),
        aug_straight_through=bool(
            raw["augmentation"]["encodec"]["straight_through"]
        ),
        recon_l1_weight=float(raw["loss"]["reconstruction_l1_weight"]),
        recon_mel_weight=float(raw["loss"]["reconstruction_mel_weight"]),
        msg_bce_weight_start=float(raw["loss"]["message_bce_weight_start"]),
        msg_bce_weight_end=float(raw["loss"]["message_bce_weight_end"]),
        msg_bce_ramp_steps=int(raw["loss"]["message_bce_ramp_steps"]),
        lr=float(raw["optimizer"]["lr"]),
        weight_decay=float(raw["optimizer"]["weight_decay"]),
        gradient_clip=float(raw["optimizer"]["gradient_clip"]),
        ckpt_interval_seconds=int(raw["checkpointing"]["interval_seconds"]),
        ckpt_keep_last_n=int(raw["checkpointing"]["keep_last_n"]),
        ckpt_keep_best=bool(raw["checkpointing"]["keep_best"]),
        step_log_interval=int(raw["logging"]["step_interval"]),
        disk_check_interval_seconds=int(
            raw["logging"]["disk_check_interval_seconds"]
        ),
        stop_flag_path=(tool_dir / raw["safety"]["stop_flag_path"]).resolve(),
        oom_retry=bool(raw["safety"]["oom_retry"]),
        deliverable_dir=Path(
            raw.get("finalize", {}).get(
                "deliverable_dir",
                "C:/local_dev_tmp/silentcipher-codec-robust",
            )
        ).resolve(),
        train_corpus=raw["data"]["train_corpus"],
        augmentation_corpus=raw["data"].get("augmentation_corpus"),
        augmentation_weight=float(raw["data"].get("augmentation_weight", 0.0)),
    )


# ============================================================================
# Data loader — LibriSpeech dev-clean (CC-BY-4.0)
# ============================================================================


class LibriSpeechClipDataset(torch.utils.data.Dataset):
    """Reads LibriSpeech FLAC files and yields fixed-length clips.

    Expects LibriSpeech in the layout torchaudio.datasets.LIBRISPEECH
    produces (typically ~/.cache/torch/hub/librispeech/dev-clean/).
    """

    def __init__(
        self,
        root: Path,
        clip_samples: int,
        sample_rate: int,
        channels: int,
    ) -> None:
        self.clip_samples = clip_samples
        self.sample_rate = sample_rate
        self.channels = channels
        # Recursively enumerate every FLAC in the corpus.
        self.files: list[Path] = sorted(root.rglob("*.flac"))
        if not self.files:
            raise RuntimeError(
                f"no FLAC files found under {root}; run "
                f"`python data/fetch_librispeech.py` first."
            )

    def __len__(self) -> int:
        return len(self.files)

    def __getitem__(self, idx: int) -> torch.Tensor:
        path = self.files[idx]
        wav, sr = torchaudio.load(str(path))
        # Resample if the file's native rate differs from target.
        if sr != self.sample_rate:
            wav = torchaudio.functional.resample(
                wav, orig_freq=sr, new_freq=self.sample_rate
            )
        # Channel handling.
        if wav.shape[0] != self.channels:
            if self.channels == 1 and wav.shape[0] > 1:
                wav = wav.mean(dim=0, keepdim=True)
            elif self.channels == 2 and wav.shape[0] == 1:
                wav = wav.repeat(2, 1)
        # Random crop / pad to clip_samples.
        n = wav.shape[-1]
        if n >= self.clip_samples:
            start = torch.randint(0, n - self.clip_samples + 1, (1,)).item()
            wav = wav[..., start : start + self.clip_samples]
        else:
            wav = F.pad(wav, (0, self.clip_samples - n))
        return wav  # shape [C, T]


def build_dataloader(cfg: Config) -> torch.utils.data.DataLoader:
    root = Path.home() / ".cache" / "torch" / "hub" / "librispeech" / "dev-clean"
    if not root.exists():
        raise RuntimeError(
            f"LibriSpeech dev-clean not found at {root}. Fetch first via "
            f"`python data/fetch_librispeech.py`."
        )
    clip_samples = int(cfg.clip_seconds * cfg.sample_rate)
    ds = LibriSpeechClipDataset(root, clip_samples, cfg.sample_rate, cfg.channels)
    return torch.utils.data.DataLoader(
        ds,
        batch_size=cfg.batch_size,
        shuffle=True,
        num_workers=2,
        pin_memory=True,
        drop_last=True,
        persistent_workers=True,
    )


# ============================================================================
# Model loading — silentcipher-specific bridge points marked SILENTCIPHER_API_TODO
# ============================================================================


def load_silentcipher(cfg: Config, device: torch.device) -> tuple[nn.Module, nn.Module]:
    """Load Sony's silentcipher encoder + decoder.

    SILENTCIPHER_API_TODO(1/4): the exact import path + constructor for
    silentcipher's model varies with package version. This function's
    job is to return (encoder, decoder) as nn.Modules. Adapt the exact
    import to whatever the installed silentcipher version exposes. The
    two modules must satisfy:
        encoder(waveform, payload) -> watermarked_waveform
        decoder(watermarked_waveform) -> logits_of_payload
    """
    if cfg.base_checkpoint is None:
        # Night 2 resume path: load from deliverable_dir/best.pt
        best = cfg.deliverable_dir / "best.pt"
        if not best.exists():
            raise RuntimeError(
                f"cfg.base_checkpoint is null (resume mode) but "
                f"{best} not found. Run night1 first."
            )
        state = torch.load(best, map_location=device)
        # Reconstruct model architecture from state dict.
        # SILENTCIPHER_API_TODO(2/4): silentcipher's model init call.
        import silentcipher  # noqa

        model = silentcipher.get_model(
            model_type="44.1k",
            device=device,
        )
        model.load_state_dict(state["model_state_dict"])
    else:
        # Fresh start from Sony's upstream checkpoint.
        # SILENTCIPHER_API_TODO(3/4): silentcipher's HF-cached loader.
        import silentcipher  # noqa

        model = silentcipher.get_model(
            model_type="44.1k",
            device=device,
        )

    encoder = model.encoder
    decoder = model.decoder
    return encoder, decoder


# ============================================================================
# Loss functions
# ============================================================================


def multi_scale_mel_loss(
    x: torch.Tensor, y: torch.Tensor, sample_rate: int
) -> torch.Tensor:
    """L1 on log-mel spectrograms at three FFT scales.

    Standard perceptual loss for audio reconstruction. Encourages the
    encoder to preserve mel-spectral energy the human ear perceives
    even when the sample-level residual is non-zero.
    """
    total = torch.tensor(0.0, device=x.device)
    for n_fft in (512, 1024, 2048):
        transform = torchaudio.transforms.MelSpectrogram(
            sample_rate=sample_rate,
            n_fft=n_fft,
            hop_length=n_fft // 4,
            n_mels=80,
        ).to(x.device)
        mx = torch.log(transform(x) + 1e-6)
        my = torch.log(transform(y) + 1e-6)
        total = total + F.l1_loss(mx, my)
    return total / 3.0


# ============================================================================
# Guards — safe-stop, disk-check, OOM
# ============================================================================


class GracefulExit(Exception):
    """Raised by signal / stop-flag handlers to end training cleanly."""


_STOP_REQUESTED = False


def _sigterm_handler(signum, frame):  # noqa: ARG001
    global _STOP_REQUESTED
    _STOP_REQUESTED = True
    yellow("SIGTERM received; will checkpoint + exit at next step boundary.")


def check_safe_stop(stop_flag: Path) -> None:
    """Raise GracefulExit if stop.flag exists OR SIGTERM was received."""
    if _STOP_REQUESTED:
        raise GracefulExit("SIGTERM received")
    if stop_flag.exists():
        yellow(f"stop.flag detected at {stop_flag}; exiting gracefully.")
        try:
            stop_flag.unlink()
        except FileNotFoundError:
            pass
        raise GracefulExit("stop.flag")


def check_disk(dir_path: Path, min_gb: float = 10.0) -> None:
    """Raise GracefulExit if free disk drops below min_gb."""
    free_gb = shutil.disk_usage(dir_path).free / (1024**3)
    if free_gb < min_gb:
        red(f"disk critically low: {free_gb:.1f} GB free (<{min_gb} GB); exiting.")
        raise GracefulExit(f"disk critical: {free_gb:.1f} GB")


# ============================================================================
# Checkpoint I/O
# ============================================================================


def save_checkpoint(
    cfg: Config,
    step: int,
    encoder: nn.Module,
    decoder: nn.Module,
    optimizer: torch.optim.Optimizer,
    val_conf_aac192: float,
    log_file: Path,
) -> Path:
    cfg.deliverable_dir.mkdir(parents=True, exist_ok=True)
    stem = f"ckpt_step{step:07d}.pt"
    dest = cfg.deliverable_dir / stem
    payload = {
        "step": step,
        "model_state_dict": {
            "encoder": encoder.state_dict(),
            "decoder": decoder.state_dict(),
        },
        "optimizer_state_dict": optimizer.state_dict(),
        "val_conf_aac192": val_conf_aac192,
        "run_name": cfg.run_name,
    }
    torch.save(payload, dest)
    log(f"checkpoint saved: {dest.name}", log_file=log_file)
    return dest


def prune_checkpoints(cfg: Config, log_file: Path) -> None:
    """Keep last N + best.pt (which is a symlink to argmax(val_conf))."""
    ckpts = sorted(cfg.deliverable_dir.glob("ckpt_step*.pt"))
    if len(ckpts) <= cfg.ckpt_keep_last_n:
        return
    to_delete = ckpts[: -cfg.ckpt_keep_last_n]
    # Never delete a checkpoint that best.pt symlinks to.
    best = cfg.deliverable_dir / "best.pt"
    best_target: Optional[Path] = None
    if best.exists():
        try:
            best_target = best.resolve()
        except OSError:
            best_target = None
    for ckpt in to_delete:
        if best_target is not None and ckpt.resolve() == best_target:
            continue
        try:
            ckpt.unlink()
            log(f"pruned old checkpoint: {ckpt.name}", log_file=log_file)
        except OSError as e:
            yellow(f"could not prune {ckpt.name}: {e}")


def link_best(cfg: Config, ckpt_path: Path) -> None:
    """Update best.pt to point at the given checkpoint."""
    best = cfg.deliverable_dir / "best.pt"
    if best.exists() or best.is_symlink():
        try:
            best.unlink()
        except OSError:
            pass
    try:
        os.symlink(ckpt_path.name, best)
    except OSError:
        # Windows without symlink permission → fall back to copy.
        shutil.copy2(ckpt_path, best)


# ============================================================================
# Training loop
# ============================================================================


def train(cfg: Config) -> int:
    # Setup logging + deliverable dir.
    cfg.deliverable_dir.mkdir(parents=True, exist_ok=True)
    log_file = cfg.deliverable_dir / "train.log"

    log(f"starting run: {cfg.run_name}", log_file=log_file)
    log(f"deliverable dir: {cfg.deliverable_dir}", log_file=log_file)

    # Determinism (seed the RNGs; not fully bit-reproducible under cuDNN
    # autotune, but batch order is stable within a seed).
    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cpu":
        red("CUDA not available; training on CPU is impractical for this run.")
        return 1

    # Model.
    encoder, decoder = load_silentcipher(cfg, device)
    encoder = encoder.to(device)
    decoder = decoder.to(device)
    if cfg.freeze_decoder:
        for p in decoder.parameters():
            p.requires_grad_(False)
        decoder.eval()

    # Encodec augmentation (Option A).
    aug = EncodecAacAugmentation(
        target_bitrate_kbps=cfg.aug_target_bitrate_kbps,
        input_sample_rate=cfg.sample_rate,
        encodec_variant="24khz" if cfg.channels == 1 else "48khz",
        stochastic=False,
    ).to(device)

    optimizer = torch.optim.AdamW(
        [p for p in encoder.parameters() if p.requires_grad],
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )

    # Data.
    loader = build_dataloader(cfg)
    log(f"dataloader ready; {len(loader)} batches / epoch", log_file=log_file)

    # Signal handler.
    signal.signal(signal.SIGTERM, _sigterm_handler)

    # State.
    step = 0
    start_time = time.time()
    last_ckpt_time = start_time
    last_disk_check = start_time
    best_val_conf = -1.0
    current_batch = cfg.batch_size

    log(
        f"training start; total_steps={cfg.total_steps} "
        f"wallclock_ceiling={cfg.wallclock_ceiling_hours}h",
        log_file=log_file,
    )

    try:
        while step < cfg.total_steps:
            for batch in loader:
                # Wallclock ceiling.
                elapsed_h = (time.time() - start_time) / 3600
                if elapsed_h >= cfg.wallclock_ceiling_hours:
                    yellow(
                        f"wallclock ceiling reached ({elapsed_h:.1f}h ≥ "
                        f"{cfg.wallclock_ceiling_hours}h); exiting."
                    )
                    raise GracefulExit("wallclock_ceiling")

                # Safe-stop.
                check_safe_stop(cfg.stop_flag_path)

                # Disk-check.
                now = time.time()
                if now - last_disk_check >= cfg.disk_check_interval_seconds:
                    check_disk(cfg.deliverable_dir)
                    last_disk_check = now

                # Move to device.
                waveform = batch.to(device, non_blocking=True)
                # shape [B, C, T]

                # Random 40-bit payload per batch (silentcipher's format).
                # SILENTCIPHER_API_TODO(4/4): silentcipher may use bytes,
                # int tensor, or per-tile bits. Adjust to the actual
                # encoder(waveform, payload) signature.
                payload = torch.randint(
                    0,
                    2,
                    (current_batch, 40),
                    dtype=torch.float32,
                    device=device,
                )

                try:
                    # Forward.
                    optimizer.zero_grad(set_to_none=True)
                    marked = encoder(waveform, payload)
                    # marked shape [B, C, T]

                    # Codec augmentation (differentiable via
                    # straight-through gradient).
                    marked_codec = aug(marked)

                    # Decode payload from codec-degraded audio.
                    logits = decoder(marked_codec)
                    # logits shape [B, 40] or [B, tiles, 40]; use last dim

                    # Reconstruction losses (imperceptibility).
                    l1 = F.l1_loss(marked, waveform)
                    mel = multi_scale_mel_loss(
                        marked.reshape(-1, marked.shape[-1]),
                        waveform.reshape(-1, waveform.shape[-1]),
                        cfg.sample_rate,
                    )

                    # Message BCE (robustness). Ramp weight over ramp_steps.
                    if cfg.msg_bce_ramp_steps > 0 and step < cfg.msg_bce_ramp_steps:
                        alpha = step / cfg.msg_bce_ramp_steps
                        bce_w = (
                            cfg.msg_bce_weight_start * (1 - alpha)
                            + cfg.msg_bce_weight_end * alpha
                        )
                    else:
                        bce_w = cfg.msg_bce_weight_end

                    # Reduce logits to [B, 40] if silentcipher emits tile-vote shape.
                    if logits.dim() == 3:
                        logits = logits.mean(dim=1)
                    bce = F.binary_cross_entropy_with_logits(logits, payload)

                    loss = (
                        cfg.recon_l1_weight * l1
                        + cfg.recon_mel_weight * mel
                        + bce_w * bce
                    )

                    # Backward + step.
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(
                        encoder.parameters(), cfg.gradient_clip
                    )
                    optimizer.step()

                except torch.cuda.OutOfMemoryError:
                    if not cfg.oom_retry:
                        raise
                    torch.cuda.empty_cache()
                    gc.collect()
                    new_batch = max(1, current_batch // 2)
                    yellow(
                        f"OOM at step {step}; halving batch "
                        f"{current_batch} → {new_batch} and retrying."
                    )
                    current_batch = new_batch
                    # Rebuild loader with new batch size.
                    cfg.batch_size = current_batch
                    loader = build_dataloader(cfg)
                    break  # restart the epoch loop with new loader

                step += 1

                # Metrics row.
                if step % cfg.step_log_interval == 0:
                    log(
                        f"step {step:6d} | loss {loss.item():.4f} | "
                        f"l1 {l1.item():.4f} | mel {mel.item():.4f} | "
                        f"bce {bce.item():.4f} (w={bce_w:.2f}) | "
                        f"batch {current_batch}",
                        log_file=log_file,
                    )

                # Checkpoint.
                if now - last_ckpt_time >= cfg.ckpt_interval_seconds:
                    # Cheap val estimate: bce on a single held-out batch
                    # would be ideal, but for speed we use the current
                    # step's bce as the "val_conf" proxy. Real val
                    # numbers come from validate.py between nights.
                    ckpt_path = save_checkpoint(
                        cfg, step, encoder, decoder, optimizer,
                        val_conf_aac192=float(1.0 - torch.sigmoid(logits).sub(payload).abs().mean().item()),
                        log_file=log_file,
                    )
                    if cfg.ckpt_keep_best:
                        # Track best by inverse-BCE-proxy.
                        proxy = float(
                            1.0
                            - torch.sigmoid(logits)
                            .sub(payload)
                            .abs()
                            .mean()
                            .item()
                        )
                        if proxy > best_val_conf:
                            best_val_conf = proxy
                            link_best(cfg, ckpt_path)
                    prune_checkpoints(cfg, log_file)
                    last_ckpt_time = now

                if step >= cfg.total_steps:
                    break

    except GracefulExit as e:
        log(f"graceful exit: {e}", log_file=log_file)
    except KeyboardInterrupt:
        log("KeyboardInterrupt; checkpointing before exit.", log_file=log_file)

    # Final checkpoint + prune.
    save_checkpoint(
        cfg, step, encoder, decoder, optimizer,
        val_conf_aac192=best_val_conf,
        log_file=log_file,
    )
    prune_checkpoints(cfg, log_file)

    log(f"training complete. best proxy val conf = {best_val_conf:.4f}", log_file=log_file)
    log(f"deliverable dir: {cfg.deliverable_dir}", log_file=log_file)
    return 0


# ============================================================================
# Entry point
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description="silentcipher codec-robust fine-tune")
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="path to night1.yaml or night2.yaml",
    )
    args = parser.parse_args()

    if not args.config.exists():
        red(f"config not found: {args.config}")
        return 2

    cfg = load_config(args.config)
    return train(cfg)


if __name__ == "__main__":
    sys.exit(main())
