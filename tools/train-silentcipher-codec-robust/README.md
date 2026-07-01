# silentcipher codec-robust fine-tune — training scaffold

Sits outside the Rust workspace (`tools/` at repo root, not `crates/`). The scaffold prepares the drop-in files for the fine-tune training run. Live design at [`docs/silentcipher-codec-robust-fine-tune.md`](../../docs/silentcipher-codec-robust-fine-tune.md).

**Current state**: scaffold + preflight only. `train.py`, `validate.py`, and `export_onnx.py` land in a follow-up iteration commit once the augmentation-code choice (Encodec Option A vs psychoacoustic Option B) is confirmed. This directory is intentionally executable-piece-by-piece so operator can validate the environment before committing to the full training loop.

## License

- Our code (this directory, minus the vendored LICENSE bundles): MIT (Creative Mayhem UG).
- silentcipher (Sony AI): MIT. See [`LICENSE-silentcipher`](./LICENSE-silentcipher) when it lands.
- Encodec (Meta FAIR): MIT (Option A augmentation).
- LibriSpeech training corpus: CC-BY-4.0 (permissive, attribution required).

Full attribution instructions in [`configs/attribution_bundle.md`](./configs/attribution_bundle.md) when it lands.

## Directory layout (target)

```
tools/train-silentcipher-codec-robust/
  README.md                            ← you are here
  requirements.txt                     ← Python deps + pinned versions
  preflight.py                         ← environment / GPU / disk / model check
  train.py                             ← main training loop (STUB)
  validate.py                          ← 5-min between-night check (STUB)
  export_onnx.py                       ← post-training encoder → ONNX export (STUB)
  configs/
    night1.yaml                        ← hyperparameters for first night
    night2.yaml                        ← hyperparameters for second night
    attribution_bundle.md              ← where in the deliverable each LICENSE goes
  codec_augmentation/
    encodec_aac.py                     ← Option A: differentiable AAC via Encodec (STUB)
    psychoacoustic.py                  ← Option B fallback: mask + quant noise (STUB)
  scripts/
    night_run.sh                       ← orchestrator: preflight → train → validate
    safe_stop.sh                       ← touch stop.flag → next step exits gracefully
  data/
    corpus_manifest.json               ← LibriSpeech + optional augmentation source spec (STUB)
```

## Bulletproofing guarantees

Everything the operator runs from this directory is designed to fail loudly rather than churn the machine:

- `preflight.py` exits 1 with a colored RED banner if the environment isn't ready (missing GPU, insufficient disk, missing model, missing Python dep). No cascade failures.
- `train.py` runs inside `tmux` (per `scripts/night_run.sh`) so a terminal disconnect doesn't kill the run. Handles SIGTERM cleanly via checkpoint-then-exit.
- Every 30 minutes, `train.py` checkpoints AND checks free disk. Under 10 GB → pause, log alert, exit. Never fills the disk.
- Checkpoints rotate: last 3 + best-so-far only. Bounded storage.
- `touch stop.flag` at repo root → next training step notices, checkpoints, exits gracefully.
- OOM handler: `train.py` wraps every training step in `try/except torch.cuda.OutOfMemoryError` → halve batch, log, retry. Self-healing.

## Two-night schedule

Full detail in [`docs/silentcipher-codec-robust-fine-tune.md`](../../docs/silentcipher-codec-robust-fine-tune.md). TL;DR:

**Night 1** (6 h):
1. Preflight (10 min)
2. Message-recovery-loss ramp (500 steps, 45 min)
3. Main run (12k steps, 4 h 45 min)
4. Validation + checkpoint prune (15 min)
5. Cushion (5 min)

**Day between** (5 min): run `validate.py` on night 1 best checkpoint. Decide green / amber / red.

**Night 2** (6 h):
1. Preflight (10 min)
2. Resume from night 1 best (10k steps, 4 h 45 min)
3. Final validation sweep (AAC 128/192 + Opus 96/128 + MP3 192 + lossless regression, 30 min)
4. ONNX export (15 min)
5. Package deliverable (10 min)
6. Cushion (10 min)

## How to use

```bash
# One-time setup (from repo root):
cd tools/train-silentcipher-codec-robust
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Before EVERY training night:
python preflight.py             # exits 0 if GREEN, 1 if RED
                                # AMBER prints suggestion but exits 0

# Only if preflight was GREEN:
./scripts/night_run.sh night1   # first night — from upstream Sony checkpoint
./scripts/night_run.sh night2   # second night — resume from night 1 best

# During a run (from any terminal on the same host):
touch stop.flag                 # graceful stop at next step boundary
tmux attach -t silentcipher-train    # observe live progress

# Between nights:
python validate.py              # 5-min checkpoint validation, print green/amber/red table
```

## What lands next

Follow-up iteration commits after this scaffold:

1. `train.py` with the message-recovery-loss ramp + main loop + guards. Estimated ~500 lines.
2. `validate.py` with the AAC/Opus/MP3/lossless sweep. Estimated ~200 lines.
3. `codec_augmentation/encodec_aac.py` (Option A primary). Estimated ~250 lines.
4. `codec_augmentation/psychoacoustic.py` (Option B fallback). Estimated ~150 lines.
5. `export_onnx.py` with attribution-bundle assembly. Estimated ~100 lines.
6. `data/corpus_manifest.json` + a small fetch script that lands LibriSpeech dev-clean into the training dir.

These land one at a time as `[skip ci]` iteration commits so operator can validate each piece independently before committing to a full-night run.

## What the training run does NOT do

Explicit non-goals for the first pass:

- Does not modify or re-release the upstream Sony silentcipher decoder. Decoder stays frozen at Sony's MIT-licensed pretrained weights; codec-robust checkpoint interoperates with existing decoder.
- Does not target speech codecs (Speex, AMR, GSM). Those are a different domain; out of scope.
- Does not target below-128-kbps AAC / Opus. Information-theoretic wall; would require different training methodology.
- Does not target arbitrary DJ-remix survival. Research territory; no shipped watermark handles this reliably in 2026.
- Does not target sub-3-second-segment recovery. Below silentcipher's tile-vote threshold.

## Reference

- [`docs/silentcipher-codec-robust-fine-tune.md`](../../docs/silentcipher-codec-robust-fine-tune.md) — the formal plan
- [`docs/audio-watermark-survival-range.md`](../../docs/audio-watermark-survival-range.md) — the range this fine-tune contributes to
- [`docs/multi-family-embed-workflow.md`](../../docs/multi-family-embed-workflow.md) — the composite delivery strategy
- Session memory drawers: `project_v0.5.2_codec_survival` (empirical AAC-survival finding); `project_gpu_embed_production_verified` (30x realtime measured on 3090)
