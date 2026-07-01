# silentcipher codec-robust fine-tune — plan

**Scope:** produce a fine-tuned silentcipher encoder checkpoint whose watermarks survive AAC ≥ 192 kbps and Opus ≥ 128 kbps re-encoding, closing the codec-survival gap between silentcipher (upstream Sony checkpoint) and AudioSeal / WavMark. Ships as a **second variant** alongside the upstream Sony checkpoint in the `provcheck-weights` DLC MANIFEST; operator selects via `provcheck-kit watermark --kind silentcipher-codec-robust`. Upstream Sony checkpoint stays unchanged and reachable via `--kind silentcipher` (default). Not a hostile fork of Sony's work — a downstream variant that ships alongside.

**Compute constraint:** 2 × 6-hour nights on a single 5090 (32 GB VRAM). Machine is user-owned; 3090 excluded because it hosts a shared Ollama service and gets occasional GPU conflicts.

**License constraint:** MIT throughout. Sony silentcipher (MIT, code + weights), LibriSpeech training corpus (CC-BY-4.0, permissive), Encodec augmentation code (Meta, MIT). Derived checkpoint ships under MIT with Sony's original LICENSE bundled + Creative Mayhem UG credit in the model card.

## Target metrics

Success criteria checked at end of night 2 by the validation script:

| Metric | Green (ship) | Amber (ship experimental) | Red (do not ship) |
|---|---|---|---|
| AAC 192 kbps detect confidence | ≥ 0.85 | 0.70 – 0.85 | < 0.70 |
| AAC 128 kbps detect confidence | ≥ 0.70 | 0.55 – 0.70 | < 0.55 |
| Opus 128 kbps detect confidence | ≥ 0.85 | 0.70 – 0.85 | < 0.70 |
| MP3 192 kbps detect confidence (regression guard) | ≥ 0.95 | 0.85 – 0.95 | < 0.85 |
| SDR (imperceptibility) | ≥ 27 dB | 22 – 27 dB | < 22 dB |
| Lossless round-trip detect confidence | ≥ 0.95 | 0.85 – 0.95 | < 0.85 |

## Training methodology

**Base model:** Sony's silentcipher encoder + decoder checkpoint at 44.1 kHz. Downloaded once via `huggingface_hub` (already in `~/.cache/huggingface/` per the pre-push gate check).

**Fine-tune target:** the encoder only. Decoder stays MIT-original frozen. Rationale: we want the encoder to emit marks that survive codec attacks; the decoder recovery behaviour on codec-degraded inputs is already characterised, and freezing it (a) halves training compute per step and (b) preserves interop — a codec-robust-encoded file is still decodable by the upstream Sony decoder.

**Augmentation** (the key technique): between the encoder's output and the decoder's input during training, inject a differentiable audio-codec approximation. Two options:

- **Option A (primary): Encodec-style straight-through gradient AAC approximation.** Take Meta's Encodec (MIT), use it as a differentiable proxy for AAC's psychoacoustic damage. Straight-through gradient lets the encoder learn where the AAC "keep mask" leaves headroom. ~200 lines of PyTorch to integrate.
- **Option B (fallback): psychoacoustic mask + quantisation noise model.** If Option A hits a wall on Encodec integration, fall back to a lighter augmentation: apply a static psychoacoustic mask (bark bands) + additive quantisation noise scaled to AAC 192 kbps target. Less faithful to AAC specifically but training-time cheaper.

**Loss function:**
- reconstruction loss (encoder output vs input): 0.6 × L1 + 0.2 × multi-scale mel
- message recovery BCE (payload survival after codec augmentation): 0.2 weight, ramp from 0 → 0.5 over first 500 steps to avoid destroying imperceptibility early

**Learning rate:** 1e-5 constant. Low enough that fine-tune preserves upstream imperceptibility profile. No warmup schedule other than the message-recovery-loss ramp.

**Batch size:** 16 clips × 5 seconds each. At 44.1 kHz that's 220,500 samples per clip × 16 = 3.5M samples per batch. Memory footprint ~12 GB at peak (measured by preflight dry-run).

**Total step budget:**
- Night 1: 12,000 steps at ~1.5 s / step = ~5 h wallclock
- Night 2 (continuation): 10,000 steps + validation sweep = ~5 h wallclock + 30 min validation

**Data corpus:**
- **Training**: LibriSpeech `dev-clean` (~350 MB, CC-BY-4.0). Speech-heavy — covers the doomscroll voice-mixdown case; broader-genre coverage would come from a music dataset if that becomes a target (out of scope for the first fine-tune).
- **Validation**: 20 held-out clips (10 speech from LibriSpeech `test-clean`, 10 music from a small MIT-licensed music corpus e.g. MusicNet or FMA free tier).
- **Optional augmentation source**: user's own archive read-streamed from NAS `Z:\`. Read-only, no local copy. Weighted mix during training biases the model toward operator's own distribution.

## Bulletproofing

### Preflight (runs before every night)

`tools/train-silentcipher-codec-robust/preflight.py`:

1. GPU visible? (nvidia-smi enumerates 5090)
2. No other CUDA process holding VRAM? (fail if >2 GB in use elsewhere)
3. Free disk ≥ 50 GB on the training dir's mount?
4. Sony's silentcipher checkpoint present in HF cache?
5. Python deps installed and importable?
6. Dry-run forward pass at batch 16, log peak VRAM, verify no OOM.
7. Emit a "GREEN / AMBER / RED" one-line report; exit 1 on RED.

### Training loop guards (`train.py`)

- `try / except torch.cuda.OutOfMemoryError` → halve batch size, log, retry. Self-heals.
- Every step: log RSS + VRAM. Every 100 steps: emit a metrics row (loss components, SDR estimate).
- Every 30 min: checkpoint → prune all but last 3 + `best.pt` (linked separately).
- Every checkpoint: check free disk; if < 10 GB → pause, log alert, exit gracefully with clean state.
- SIGTERM / Ctrl-C handler → clean checkpoint + exit.
- **Safe-stop file**: `touch stop.flag` at repo root → next step notices, checkpoints, exits gracefully.
- Runs inside `tmux` session (`session name: silentcipher-train`) so a disconnect / reboot doesn't kill the run.

### Between-night validation (`validate.py`)

5-minute script:
1. Load latest checkpoint.
2. Run 20-sample validation set through: encode → AAC 192k → decode → detect confidence.
3. Report SDR + detect conf table + green / amber / red banner.
4. If red, print suggested config adjustment (LR halve, augmentation weight halve, etc.).

## Night-by-night schedule

### Night 1 (6 h) — main fine-tune from upstream Sony checkpoint

| Phase | Duration | Detail |
|---|---|---|
| Preflight | 10 min | preflight.py, halt on any RED |
| Message-recovery-loss ramp | 45 min | first 500 steps ramp message-recovery loss weight 0 → 0.5 while keeping reconstruction dominant; stabilises imperceptibility |
| Main run | 4 h 45 min | encoder-only fine-tune, decoder frozen, Encodec-augmented codec attack in the loop |
| Validation + prune | 15 min | validate.py + checkpoint dir cleanup |
| Cushion | 5 min | |

Expected end-of-night-1 metrics: SDR ≥ 28 dB, AAC 192 kbps detect confidence ≥ 0.75.

### Day between (5 min hands-on)

Run `validate.py` on the night 1 best checkpoint. Decision:
- **Green**: continue with same config into night 2.
- **Amber**: halve LR, halve message-recovery-loss weight, restart night 2 from night 1 best.
- **Red**: keep night 1 best as fallback, restart night 2 from upstream checkpoint with Option B augmentation.

### Night 2 (6 h) — continuation + finalise

| Phase | Duration | Detail |
|---|---|---|
| Preflight | 10 min | |
| Resume from night 1 best | 4 h 45 min | 10,000 more steps at tuned config |
| Final validation sweep | 30 min | AAC 128k / 192k + Opus 96k / 128k + MP3 192k, on 20-clip val set |
| ONNX export | 15 min | encoder → `encoder.onnx`, verify byte identity of a fresh detect against the .pt checkpoint |
| Package deliverable | 10 min | assemble the deliverable bundle described below |
| Cushion | 10 min | |

## Deliverable structure

```
work/silentcipher-codec-robust/
  README.md                    (methodology + validation table + how to reproduce)
  LICENSE                      (Creative Mayhem UG MIT)
  LICENSE-silentcipher         (Sony's original MIT — bundled)
  LICENSE-encodec              (Meta's MIT — bundled if Option A augmentation was used)
  LICENSE-librispeech          (CC-BY-4.0 attribution for training corpus)
  encoder.onnx                 (~150 MB — the artefact provcheck-weights adds as a new variant)
  encoder.pt                   (PyTorch state dict, best of run)
  model_card.md                (training data, hyperparams, validation numbers, imperceptibility examples)
  validation/
    aac_128k_confs.csv
    aac_192k_confs.csv
    opus_96k_confs.csv
    opus_128k_confs.csv
    mp3_192k_confs.csv
    lossless_confs.csv
    sample_examples/           (10 before/after audio clips to hear the imperceptibility)
  train.log                    (~10 MB, tail -f-able during the run)
  configs/
    night1.yaml                (as used)
    night2.yaml                (as tuned between-nights)
```

Total deliverable footprint: ~500 MB. Slotting into `provcheck-weights`:

1. Compute SHA-256 of `encoder.onnx`.
2. Append MANIFEST entry: `family: "silentcipher"`, `variant: "codec_robust_v1"`, `url` pointing at the `weights-v1` (or `weights-v2` — see below) GitHub Release upload, `sha256`, `size`.
3. Add `WatermarkKind::SilentCipherCodecRobust` variant OR reuse `WatermarkKind::SilentCipher` with a `variant` selector — the choice is deferred to the integration commit (probably the second: adds a `--variant codec-robust` flag on `--kind silentcipher` for CLI ergonomics and no wire-format break).
4. Ship via `weights-v2` if the MANIFEST additions are semver-minor OR reuse `weights-v1` with a partial-content-update entry — decision at integration time based on how many other DLC changes are pending.

## Provcheck-side integration plumbing (prepared, not committed)

Preparation only; actual wiring lands in a follow-up iteration commit once training produces an ONNX + SHA:

1. `crates/provcheck-weights/src/manifest.rs`: placeholder MANIFEST entry with a TODO SHA (marked `unimplemented!()` guarded).
2. `crates/provcheck-kit/src/commands/mod.rs` watermark subcommand: add a `--variant codec-robust` flag on `--kind silentcipher` (default upstream Sony variant); clap-visible + doc-commented.
3. `provcheck-weights::load_if_cached` path: reuse existing family/variant lookup — no code path change.
4. `crates/provcheck-watermark/src/lib.rs`: existing `detect` path is already agnostic to which encoder produced the mark (detector is generic on payload); no change needed.

## Risk table

| Risk | Impact | Mitigation |
|---|---|---|
| Sony's training code is academic-grade / brittle | +1 day setup | Isolate training script in `tools/` outside workspace; iterate freely without churning the release cadence |
| Encodec integration lands hard | Fall back to Option B | Both augmentation paths documented; night 2 restarts with Option B if night 1 shows Option A pathological |
| Fine-tune destroys imperceptibility (SDR < 22 dB) | Red banner, don't ship | Message-recovery-loss ramp; validate.py catches at first checkpoint; adjust augmentation weight |
| 5090 gets pulled for other work mid-night | Loss of a run | tmux + safe-stop file → checkpoint + exit gracefully; resume from last checkpoint on next window |
| Disk fills up (checkpoints + logs) | Training halts | Rotation policy: last 3 + best-so-far only; disk-check every 30 min |
| Output silently regresses on lossless | Ship-blocking | validate.py runs lossless as a regression guard column |

## After the run: what happens if it works

- ONNX + model card + validation numbers land in the deliverable directory.
- Follow-up iteration commit wires `provcheck-weights` MANIFEST + kit CLI variant flag. That commit is `[skip ci]` until an operator issues a "build" — at which point the next `v*.x.0` cuts a release with the codec-robust variant available as a DLC.
- Range table in [`audio-watermark-survival-range.md`](./audio-watermark-survival-range.md) updates the silentcipher-fine-tune column from "planned" to "shipped" with the empirical numbers.
- Memory drawer `project_silentcipher_codec_robust_shipped.md` captures the outcome + reproduction pointer.

## After the run: what happens if it doesn't work

- Best checkpoint stays in `work/silentcipher-codec-robust/` for future work; not shipped.
- Range table stays with silentcipher-fine-tune column as "planned" / "in-progress".
- Memory drawer `project_silentcipher_codec_robust_attempted.md` captures what was tried, what failed, and the follow-up leads (Option B, different LR, different augmentation strength).
- AudioSeal + WavMark continue to be the AAC-delivery path via the multi-family workflow in [`multi-family-embed-workflow.md`](./multi-family-embed-workflow.md).

## Reference docs

- [`audio-watermark-survival-range.md`](./audio-watermark-survival-range.md) — the honest range this fine-tune contributes to
- [`multi-family-embed-workflow.md`](./multi-family-embed-workflow.md) — how the resulting variant slots into the multi-family embed
- [`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md) — the FOSS-license constraints preserved throughout
- Memory drawer `project_v0.5.2_codec_survival.md` (session-local) — the 2026-06-24 empirical parity sweep that produced the "silentcipher cannot survive AAC at any setting" finding this fine-tune tries to overturn
