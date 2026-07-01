# provcheck

**Install:** [release binary](https://github.com/CreativeMayhemLtd/provcheck/releases)
(Windows / Linux / macOS, CLI + GUI) · or `cargo install provcheck-cli` · or
[build from source](https://github.com/CreativeMayhemLtd/provcheck/archive/refs/heads/main.zip).

---

**Verify and produce C2PA Content Credentials, on any platform, for any
vendor — with a creator identity bound to an atproto DID and a neural
watermark cross-check on top.**

[C2PA](https://c2pa.org) is the open content-provenance standard backed
by Adobe, Microsoft, the BBC, and the major digital camera makers.
provcheck does two things with it:

- **`provcheck`** (the verifier) — point it at a file and it tells you
  who signed it, what tool produced it, which AI model generated it (if
  any), the chain of edits back to the source, AND whether the file
  carries a recognised neural watermark from a known brand.
- **`provcheck-kit`** (the creator-side toolkit) — mint a signing cert,
  sign your media, and publish the cert fingerprint to your atproto
  identity. Verifiers downstream can then cross-check that the signature
  really did come from the handle on the file.

No account. No web upload. No vendor lock-in. The file stays on your
machine. The verifier is offline. The kit only talks to atproto when
you run `publish` or `verify`.

## Status

**v0.9.0 shipped 2026-06-29.** Video and SynthID-text **watermark**
detection now run real algorithms — per-frame TrustMark + temporal
vote on the video side, Bayesian tournament-sampling z-score on
the text side. (These are watermark detectors — TrustMark by Adobe,
SynthID-text by Google. They detect content that was deliberately
marked at generation time. They are NOT deepfake detectors.) The
ComfyUI node is live, shelling out to `provcheck-kit stamp` per
generation, brand-agnostic for any creator running their own
pipeline. The CUDA EP fallback bug from public issue #32 is fixed;
default CPU builds unaffected.

Deepfake detection (asking "is this AI-generated even without a
watermark?") is a separate problem and not shipped in this repo
at any version. The v0.9 plumbing exposes a `Detector` trait so
operators can wire their own classifier (commercial pack as
paid DLC after v1.0, or an existing open-source third-party
detector — bring-your-own-model either way). See
`docs/v0.9-roadmap/README.md` section 9b for the precise contract.

"Redhat the provenance market" — every newly-added user-facing
surface for watermark detection + provenance signing is in the
Apache-2.0 FOSS core.

**v0.7.0 shipped 2026-06-28.** Multimodal expansion: image
watermarking (TrustMark-B by Adobe / Content Authenticity
Initiative) lands as a fully wired detector + embedder with
BCH-5 ecosystem interop, the kit gains a one-call creator
pipeline (`kit stamp`), every detector's weights move to a
download-on-demand DLC pattern that drops the kit binary from
~143 MB to ~22 MB, and the verifier extends to video + text
modalities (fully wired in v0.9.0: per-frame TrustMark with
temporal majority-vote on the video side, Bayesian
tournament-sampling z-score on the SynthID-text side).
"Always respect the user" — weights never auto-download.

Both CLI binaries (`provcheck`, `provcheck-kit`) and the desktop
GUI ship as pre-built downloads for Windows / Linux /
macOS-aarch64. The creator-side flow (mint identity → sign →
publish to atproto → verifier cross-checks) is production-ready
and battle-tested against rAIdio.bot music renders and
doomscroll.fm voice mixdowns. v0.6.0 closes the throughput +
memory + GPU story for long-form audio; v0.7.0 expands to
multimodal (image + video scaffold + text scaffold + DLC weight
delivery slimming the kit from ~143 MB to ~22 MB); v0.9.0
wires the video + text modalities through with real algorithms
and lands the ComfyUI node. The v0.9.x line carries the
pre-v1.0 test-coverage push (iteration tags only; see
CONTRIBUTING.md "Release cadence").

**v0.6.0 headlines:**

- **CUDA backend** for the silentcipher embed encoder via the new
  `cuda` feature flag (`cargo build --release --features cuda
  --bin provcheck-kit`). 56-minute stereo episode embed drops from
  29 minutes on a 4-wide CPU (v0.5.4's 2× real-time baseline was
  ~70 min — v0.6.0 already shaves that) to **6.6 minutes on an
  NVIDIA 3090** (0.12× real-time). Routes through `ort` 2.x's
  `CUDAExecutionProvider`. Operator installs `onnxruntime-gpu` +
  CUDA 12.x + cuDNN; NVIDIA libraries are not redistributed per
  their licensing. Default download stays a single tract-only CPU
  binary; the CUDA build is opt-in.
- **Streaming embed** that never materialises the full
  spectrogram. New `--memory-budget streaming` value on `kit
  watermark` runs a two-pass chunk-fused pipeline (pass 1 streams
  utterance_norm, pass 2 streams the chunk loop directly into an
  overlap-add ring-buffer iSTFT). On a 56-minute stereo episode
  peak RSS drops from 11.5 GB (default 4-wide mode) to 5.0 GB.
  Trade-off is ~1.6× real-time wall clock vs default's 0.52×.
  Ships for memory-constrained operators on 8-16 GB containers.
- **Chunk-parallel embed.** Default mode now uses rayon to fan
  out up to 4 chunks of silentcipher encoder inference per call,
  matching the detector-side P1 pattern. Delivers the 4× CPU
  speedup baseline above; the `--memory-budget low` knob backs it
  off to sequential for memory-constrained hosts.
- **Kit serve mode.** New `kit serve` subcommand exposes the
  watermark embed pipeline over a JSON-line stdin/stdout
  protocol. Single model load amortised across an entire batch;
  the cold-start tract optimisation pass (about 3 seconds) runs
  once instead of once per file. Built for batch-processing
  consumers like doomscroll.fm's nightly cycle.

**v0.5.x highlights:**

- **v0.5.3:** AAC-in-MP4/M4A detector priming fix. symphonia 0.5.5's
  `isomp4` reader does not surface the MP4 `edts/elst` edit list or
  the `iTunSMPB` tag as `codec_params.delay`, so prior to v0.5.3 every
  STFT frame on AAC-in-MP4/M4A was one AAC frame out of phase with
  the embedder's frame grid and detection returned conf 0.000. The
  fix hardcodes the standard 1024-sample AAC LC priming when
  symphonia leaves `delay = None` for an AAC track, and adds `mp4`,
  `m4b`, and `mov` to the audio-extension allowlist. Public issue #24.
- **v0.5.2:** Stereo embed. New `--channels {auto, mono, stereo}` on
  `kit watermark` runs two independent mono embeds with the same
  payload so a stereo delivery pipeline keeps the mark across the
  downmix-then-upmix roundtrip. silentcipher default SDR drops 47 ➝
  30 dB so libmp3lame 192k delivery survives at conf 0.95+. AudioSeal
  default alpha rises 1.0 ➝ 3.0 so both AAC 192k and libmp3lame 192k
  delivery survive at conf 0.999. Always-on `--verify-after-embed`
  self-test deletes the output file and exits non-zero when the
  freshly-embedded mark fails to detect at conf >= 0.50. Public
  issue #23.
- **v0.5.1:** silentcipher embed OOM fix on multi-minute MP3s. Public
  issue #17.
- **v0.5.0:** Hardware-backed identity custody via Yubikey PIV slot
  9c. `provcheck-kit init --yubikey` mints an ES256 keypair on-device;
  the private key is never extractable, every signature gates on the
  PIV PIN. A new GUI "Keys" tab shows local-vs-atproto state side by
  side, surfaces mismatches (superseded local key, orphan active
  record), and offers one-click revoke and rotate without dropping
  to a terminal. See
  [For creators — sign + publish](#for-creators--sign--publish) below.

All three neural-watermark detector families ship live: silentcipher
40-bit payload at 44.1 kHz, AudioSeal 16-bit ECC-protected brand ID
at 16 kHz, WavMark 32-bit payload at 16 kHz. Verifier output carries
per-detector time-span localisation (`marked_regions`); both the CLI
text report and the GUI timeline strip show where inside the audio
the mark sits. Codec compatibility matrix and parity-vs-upstream
findings live in [`docs/v0.5.2-codec-survival/`](docs/v0.5.2-codec-survival/).

## Install

### First-run: install the detector weights you need

provcheck ships a slim binary (~20 MB) and pulls detector weights
on demand from the public release. You install one family at a
time, on your terms — nothing downloads behind your back.

```bash
# See what's available + which families you have
provcheck-kit weights status

# Install one family (downloads + SHA256 verifies + caches under
# the OS-conventional location)
provcheck-kit weights install silentcipher      # 11 MB
provcheck-kit weights install audioseal         # 89 MB
provcheck-kit weights install wavmark           # 16 MB
provcheck-kit weights install trustmark         # 62 MB

# Remove what you do not need
provcheck-kit weights uninstall wavmark
```

If you run `provcheck file.mp3` (or `kit watermark`) without the
matching family installed, the verifier surfaces a clean error
naming the install command. No silent network calls.

There is intentionally no `--all` shortcut: the consent is per-
family. The `PROVCHECK_WEIGHTS_CACHE_DIR` environment variable
overrides the default cache location (useful for read-only
filesystems and CI mirrors).

### Pre-built binaries (recommended)

Download from the [Releases page](https://github.com/CreativeMayhemLtd/provcheck/releases):

**CLI:**
- `provcheck-v<version>-{windows-x86_64.zip, linux-x86_64.tar.gz, macos-aarch64.tar.gz}`
- `provcheck-kit-v<version>-{windows-x86_64.zip, linux-x86_64.tar.gz, macos-aarch64.tar.gz}`

**GUI desktop app:**
- `provcheck-gui-v<version>-x64-setup.exe` (Windows NSIS)
- `provcheck-gui-v<version>-x64-en-US.msi` (Windows MSI)
- `provcheck-gui-v<version>-amd64.deb` (Debian/Ubuntu)
- `provcheck-gui-v<version>-amd64.AppImage` (any Linux)
- `provcheck-gui-v<version>-aarch64.dmg` (macOS Apple Silicon)

Each archive carries a `.sha256` sidecar. Releases also ship per-binary
CycloneDX 1.6 + SPDX 2.3 SBOMs (`provcheck-v<version>.{cdx,spdx}.json`
and `provcheck-kit-v<version>.{cdx,spdx}.json`), consumable by
Dependency-Track, Trivy, Grype, Snyk, GitHub Advanced Security, and
other supply-chain scanners — see [`docs/sbom.md`](./docs/sbom.md).

<!-- TODO: remove the next sentence when EV code signing (SSL.com) ships. -->
Bundles are currently unsigned — Gatekeeper / SmartScreen will warn on
first launch.

Intel Mac users: run the Apple Silicon binary through Rosetta, or use
`cargo install` below.

### Via cargo (any platform with a Rust toolchain)

Install pinned to a release tag, straight from this repo:

```bash
cargo install --locked --git https://github.com/CreativeMayhemLtd/provcheck \
    --tag v0.7.0 provcheck-cli              # verifier
cargo install --locked --git https://github.com/CreativeMayhemLtd/provcheck \
    --tag v0.7.0 provcheck-kit              # signing kit
```

`--locked` enforces the upstream `Cargo.lock` for reproducible builds.
Bump the `--tag` to whatever shows in [Releases](https://github.com/CreativeMayhemLtd/provcheck/releases).

> **Why not `cargo install provcheck-cli` from crates.io?**
> Only `provcheck-cli` is currently published on crates.io, and it's
> frozen at `0.1.1` (many minor versions behind). `provcheck-kit`,
> `provcheck`, `provcheck-sign`, and `provcheck-publish` are not on
> crates.io at all. Until the full workspace is published, the
> `--git --tag` form above is the only way to get current code from
> cargo.

If you've already cloned the repo, the path-based form also works:

```bash
cargo install --locked --path crates/provcheck-cli
cargo install --locked --path crates/provcheck-kit
```

On Debian/Ubuntu the cargo install also needs these system packages:

```bash
apt-get install -y pkg-config libssl-dev libpcsclite-dev libdbus-1-dev
# runtime: libpcsclite1 (provcheck-sign links libpcsclite unconditionally)
```

On Fedora/RHEL:

```bash
dnf install -y pkgconf-pkg-config openssl-devel pcsc-lite-devel dbus-devel
```

(PR #25 + #26 by @neitzert, applied 2026-06-28.)

### In a Docker container (e.g. for a render pipeline)

```dockerfile
FROM debian:bookworm-slim
ARG PROVCHECK_VERSION=v0.5.0
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /tmp/kit.tar.gz \
    "https://github.com/CreativeMayhemLtd/provcheck/releases/download/${PROVCHECK_VERSION}/provcheck-kit-${PROVCHECK_VERSION}-linux-x86_64.tar.gz" \
 && tar -xzf /tmp/kit.tar.gz --strip-components=1 -C /usr/local/bin/ \
 && rm /tmp/kit.tar.gz
```

## Try it

Two example signed files ship with the repo plus two unsigned controls:

```bash
provcheck examples/rAIdio.bot-sample.mp3        # signed music clip
provcheck examples/doomscroll.fm-sample.mp4     # signed video bumper
provcheck examples/unsigned-sample.mp3          # no manifest — reports unsigned
provcheck examples/unsigned-sample.mp4
```

See [`examples/README.md`](./examples/README.md) for what's in each.

## Verify

Human-readable:

```bash
provcheck my-song.wav
```

Machine-readable (stable JSON schema — matches `provcheck::Report`):

```bash
provcheck --json my-song.wav
```

Silent pipeline mode (exit code only):

```bash
if provcheck --quiet my-song.wav; then
  echo "signed + verified"
fi
```

### Identity cross-check (the atproto half)

If a creator has published their signing cert to their atproto identity,
you can ask provcheck to second-factor the signature against their
handle or DID:

```bash
provcheck mix.wav --bsky-handle creator.bsky.social
provcheck mix.wav --did did:plc:abc123
provcheck mix.wav --auto-identity        # use the embedded identity assertion
```

`--auto-identity` works when the file was signed by `provcheck-kit
sign --embed-identity` — the creator's DID travels with the asset and
the verifier auto-fills the cross-check without the recipient typing
anything.

The cross-check fetches the creator's `app.provcheck.signingKey`
records over atproto and verifies that the certificate fingerprint on
the file is one they've published. **`--require-attested` makes the
cross-check a hard gate** — files whose signers can't be attested
fail with exit code 1.

### Watermark detection

provcheck runs three neural-watermark detectors on every audio input
by default — silentcipher, AudioSeal, and WavMark, in registration
order. Each returns a payload, a confidence score, and (for AudioSeal
and WavMark per-sample / per-window, and for silentcipher per-tile)
a list of `(start, end)` time spans where the watermark was detected.
The brand classifier maps known payloads to known brands across all
three families using a shared numeric registry plus silentcipher's
legacy ASCII triplet format.

```bash
provcheck my-song.mp3                    # all three detectors run
provcheck --no-watermark my-song.mp3     # skip the detectors
provcheck --require-watermark my-song.mp3 # exit 1 if no detector hits
```

A `--require-watermark` run passes if at least one of the three
detectors fires; they're independent and a file marked by one family
typically won't trigger the others.

Detectors run only on audio inputs. Image and video paths skip them.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | File carries a valid C2PA manifest that verified. |
| `1` | File is unsigned, manifest is invalid / tampered, or a `--require-*` gate failed. |
| `2` | I/O error, unreadable file, or internal error. |

`--require-trusted`, `--require-attested`, and `--require-watermark`
all gate exit code 1 the same way.

## For creators — sign + publish

The `provcheck-kit` binary handles the producer side: mint a signing
certificate, sign your media, and publish the cert fingerprint to your
atproto identity. Anyone verifying with `provcheck` can then
cross-check the signature against you.

```bash
# One-time setup (software backend — default)
provcheck-kit init                          # mint a fresh ES256 keypair
provcheck-kit login -u me.bsky.social       # attach an atproto identity
provcheck-kit publish                       # publish the cert fingerprint

# OR one-time setup (Yubikey backend, v0.5.0+)
ykman piv access change-pin                 # one-time; refuse factory default
provcheck-kit init --yubikey                # mint on PIV slot 9c, key non-extractable
provcheck-kit login -u me.bsky.social
provcheck-kit publish

# Sign + verify a file (works the same regardless of backend)
provcheck-kit sign mix.wav --embed-identity # Yubikey: prompts for PIN
provcheck mix.wav --auto-identity           # verifies + cross-checks the atproto record
```

`provcheck-kit --help` shows the full command list. Headlines:

- **`init`** — mint a fresh ES256 keypair + cert. Default backend is
  the OS keychain; pass `--age-file` for an age-encrypted file
  (headless / CI hosts), or `--yubikey` to generate the key on a
  YubiKey PIV slot 9c (private key never leaves the device, every
  signature gates on the PIV PIN). The Yubikey path refuses the
  factory-default PIN — change it via `ykman piv access change-pin`
  first.
- **`login` / `logout`** — manage your atproto session.
- **`sign`** — sign an asset in place via temp-file + atomic rename.
  `--embed-identity` adds the `app.provcheck.identity` C2PA assertion
  so verifiers auto-fill the handle. `--action <created|published|edited|opened>`
  sets the C2PA action; defaults to `published` when the source already
  has a manifest (publisher-attestation case, see below).
- **`publish`** — push your cert fingerprint to atproto as an
  `app.provcheck.signingKey` record.
- **`list`** — list every signing-key record under your DID, active and
  retired.
- **`revoke`** — stamp `validUntil = now` on a record, optionally
  linking a successor via `supersededBy`. Audit-preserving — the record
  stays in atproto history as a tombstone.
- **`rotate`** — mint a fresh key, publish it, revoke the old one with
  `supersededBy` linkage, atomic. Auto-backs the old identity up.
- **`export-backup` / `import-backup`** — age-format backups,
  passphrase or X25519-recipient encrypted. Recovery-recipient set is
  configurable (see `add-/list-/remove-recovery-recipient`).

What the kit gives you:

- **Identity custody** — private keys live in your OS keychain
  (Keychain on macOS, Credential Manager on Windows, Secret Service on
  Linux), in an age-encrypted file with optional recovery recipients
  for break-glass restore, or on a YubiKey PIV slot (key never
  extractable, PIN-gated per signature).
- **C2PA signing** — wraps the c2pa-rs builder with a sensible default
  manifest; pass `--manifest` for custom JSON.
- **Publisher-attestation re-sign** — sign a file that already carries
  a C2PA manifest and the kit auto-chains your signature on top as a
  derivative. Useful when a publisher attests an upstream creator's
  rendered output without losing the creator's provenance.
- **Atproto lifecycle** — full CRUD on signing-key records, with
  rotation primitives that keep the audit trail intact.

Full spec: [`docs/atproto-signing-key.md`](docs/atproto-signing-key.md).

## For batch processors — throughput, memory, GPU (v0.6.0)

Long-form audio pipelines (podcast cycles, music render queues,
broadcast feeds) hit the silentcipher embed harder than single-track
creators. v0.6.0 ships four knobs for tuning the embed path to the
host shape:

```bash
# Default mode: chunk-parallel rayon up to 4-wide. Best wall clock
# on a host with > 16 GB free RAM. About 0.5x real-time on a 56-min
# stereo episode (a 56-min file embeds in 29 minutes).
provcheck-kit watermark long.mp3 -o long.wav

# Sequential chunks. Trades wall clock for memory; pick this on
# 8-16 GB containers where the default mode's 4-wide rayon peak
# (~11 GB on a 56-min stereo file) is over budget.
provcheck-kit watermark long.mp3 -o long.wav --memory-budget low

# Streaming chunk-fused embed. Two-pass design that never
# materialises the full spectrogram. Peak RSS drops to ~5 GB on a
# 56-min stereo file at the cost of ~1.6x real-time (about 92 min).
# Pick this on memory-constrained hosts or for the deepest RSS cap.
provcheck-kit watermark long.mp3 -o long.wav --memory-budget streaming

# Batch-mode JSON-line worker. Reads `{"id": ..., "input": ...,
# "output": ..., "kind": ..., "payload": ..., ...}` requests on
# stdin, emits `{"id": ..., "ok": true|false, ...}` responses on
# stdout. Single model load amortised across all requests in the
# session (cold-start tract optimisation runs once, not once per
# file). Suited for long-running render queues.
provcheck-kit serve <requests.jsonl >responses.jsonl
```

**CUDA backend (opt-in build):** build the kit with `--features
cuda` to route the silentcipher embed encoder through `ort` 2.x's
`CUDAExecutionProvider`. On an NVIDIA 3090 a 56-minute stereo
episode embeds in **6.6 minutes** (0.12× real-time, ~10× faster
than the v0.5.4 baseline). Operator installs `onnxruntime-gpu` +
CUDA 12.x + cuDNN; the kit dlopens them at runtime via the
`ORT_DYLIB_PATH` env var. NVIDIA libraries are not redistributed
in our release archives per their license terms.

```bash
# Build the CUDA-enabled kit (separate target dir keeps the
# default tract-only binary untouched).
CARGO_TARGET_DIR=./target-cuda cargo build --release --features cuda --bin provcheck-kit

# At runtime, point the dlopen at the onnxruntime DLLs.
# On Windows after `pip install --user onnxruntime-gpu`:
export ORT_DYLIB_PATH=<onnxruntime-gpu install>/onnxruntime/capi/onnxruntime.dll
export PATH="$PATH;C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.8/bin"

./target-cuda/release/provcheck-kit watermark long.mp3 -o long.wav
```

Full design notes including the per-host trade-off matrix:
[`docs/v0.6.0-roadmap/`](./docs/v0.6.0-roadmap/).

## Watermark detection — what we ship

provcheck ships three fully-implemented neural-watermark detectors,
each in its own sibling crate (`provcheck-watermark`,
`provcheck-audioseal`, `provcheck-wavmark`). The verifier runs all
three on every audio input and reports each independently.

**silentcipher** is the audio watermark used by doomscroll.fm and the
rAIdio.bot music pipeline. 40-bit ASCII triplet payload at 44.1 kHz.
The detector runs the official silentcipher ONNX decoder via tract,
applies VCTK energy rescale + periodic-Hann STFT, and decodes
21-symbol tiles into 5-byte brand payloads. Per-tile match fraction
against the global mode produces the `marked_regions` time-spans.

**AudioSeal** is the Meta FAIR watermark from ICML 2024
([arXiv:2401.17264](https://arxiv.org/abs/2401.17264)). 16 kHz
time-domain pipeline using a fully-convolutional SEANet encoder +
LSTM bottleneck. 16-bit payload carries a 5-bit brand ID with
3-copy ECC (handles AudioSeal's ~6 % per-bit error). Per-sample
presence probability drives time-span localisation. New
`provcheck-kit watermark --kind audioseal --brand-id 1` embeds.

**WavMark** is a 2023 academic release
([arXiv:2308.12770](https://arxiv.org/abs/2308.12770)). 16 kHz
STFT-based pipeline using a HiNet invertible neural network.
32-bit payload split into a 16-bit fix-pattern (the detection
signal) and a 16-bit ECC-protected brand ID sharing the AudioSeal
registry. Sliding-window decode at 50 ms steps gives ~50 ms region
resolution. New `provcheck-kit watermark --kind wavmark --brand-id 1`
embeds.

All three detectors push results into `Report.watermarks` as
independent entries; downstream consumers iterate the vec to render
the timeline strip (CLI text mode, GUI per-detector horizontal bar)
or aggregate confidence across families.

License posture: only watermark detectors with FOSS-compatible code
AND model weights are accepted (all three above are MIT). See
[`WATERMARK_LICENSE_POLICY.md`](./WATERMARK_LICENSE_POLICY.md) for the
acceptance criteria and the per-detector survey.

Power-user diagnostic tools (binary dump, cross-implementation diff,
sample-shift alignment) live in
[`docs/v0.3.3-detection-gap/`](./docs/v0.3.3-detection-gap/) and the
matching examples in
[`crates/provcheck-watermark/examples/`](./crates/provcheck-watermark/examples/).
They double as the regression suite — running them against a
Python reference will catch any future symphonia / tract / model
upgrade that would reopen the v0.3.3 LAME-trim gap.

## Supported formats

Whatever the upstream [`c2pa` crate](https://crates.io/crates/c2pa)
supports — currently WAV, MP3, JPEG, PNG, HEIC, AVIF, WebP, MP4, MOV.
The crate's format list is authoritative.

Watermark detection currently runs on audio formats only (MP3, WAV).

## SBOMs

Every release ships a CycloneDX 1.6 + SPDX 2.3 SBOM for each binary
(`provcheck-<tag>.cdx.json`, `provcheck-<tag>.spdx.json`, plus the
matching pair for `provcheck-kit`). Sidecar files in the release
assets, with `.sha256` integrity checks. Tooling-ready for
Dependency Track, Trivy, Grype, Snyk, GitHub Advanced Security, and
any other supply-chain scanner that speaks either format.

Full SBOM rationale, consumption recipes, and the local-reproduction
script are in [`docs/sbom.md`](./docs/sbom.md).

## Why this exists

AI-generated content needs a trustable provenance signal or every
downstream ingester (archives, platforms, newsrooms, journalists) has
to guess. C2PA is the open standard for the cryptographic half;
atproto is what we use to make the signer's identity portable.
silentcipher is what we use to detect a known brand-stamp even when
C2PA has been stripped.

Adobe's `c2patool` and `contentcredentials.org` are the reference
implementations for C2PA itself — useful tools, but neither is a
cross-platform desktop verifier you can ship inside other software,
nor do they include identity binding or watermark cross-check.

provcheck fills those gaps. It:

- runs locally (files never leave your machine),
- ships as single binaries plus a small GUI,
- is free, permissively licensed (Apache-2.0),
- is bundled with [rAIdio.bot](https://raidio.bot) and the
  [doomscroll.fm](https://doomscroll.fm) pipeline,
- works on ANY C2PA-signed content, not just ours.

## Release history

| Version | Date | Highlights |
|---|---|---|
| **v0.9.86** | 2026-07-01 | **Code-signing scaffold lands — SSL.com eSigner cloud path wired locally, ready for v1.0.0 CI activation.** New file `scripts/sign_release.ps1` (~150 lines, PowerShell): Authenticode signer for Windows binaries via SSL.com's `CodeSignTool`. Reads config from a `signing.json` at repo root (GITIGNORED), pulls SSL.com credentials from either (a) Windows Credential Manager under a named target (local dev machine, no plaintext on disk) OR (b) inline `username` + `password` fields (CI runners materialising from GitHub Secrets). CodeSignTool derives the per-sign OTP from SSL.com's base64 `secret_code` (NOT a base32 authenticator seed — the base64 vs base32 confusion cost a full session upstream; sign_release.ps1 hard-fails if `totp_secret` is missing rather than silently trying a fallback). Signed → optional signtool verify → audit log append. New file `signing.json.example` at repo root documents the config shape with in-file comments. `.gitignore` adds `signing.json` (config with secrets) + `provcheck-signing.log` (default audit log path). `docs/release-process.md` adds a full "Code-signing (Windows binaries)" section: what gets signed (`provcheck.exe`, `provcheck-kit.exe`, `provcheck-app.exe`, NSIS setup, MSI), local + CI procedures, the four GitHub Secrets the CI wiring needs (`SSL_COM_USERNAME` / `PASSWORD` / `CREDENTIAL_ID` / `TOTP_SECRET`), the base64-vs-base32 gotcha with a "do NOT try YubiKey" callout, and verification via `Get-AuthenticodeSignature`. `SECURITY.md` "Scope" section gets a "Windows binary integrity" bullet describing the SSL.com OV cert chain (Creative Mayhem UG → SSL.com Code Signing Intermediate CA RSA R1), RFC-3161 timestamping so signatures survive cert expiry, and the release-line-tags-only constraint (iteration tags aren't signed). **NOT wired yet:** `.github/workflows/release.yml` still produces unsigned artefacts; the CI activation lands in v1.0.0 after the four Secrets are set on the dev repo and the exposed-in-development `totp_secret` is rotated on SSL.com. Doc + script commit; no CI-behaviour change until v1.0.0. |
| **v0.9.85** | 2026-07-01 | **cargo audit diff pass — one new advisory folded into SECURITY.md tolerated table.** Ran `cargo audit` against the workspace `Cargo.lock` + a fresh app/src-tauri lock generation. Four existing tolerated advisories still present (RUSTSEC-2023-0071 rsa, RUSTSEC-2024-0436 paste, RUSTSEC-2024-0370 proc-macro-error, RUSTSEC-2026-0173 proc-macro-error2); none cleared upstream. One NEW advisory surfaced that isn't in the table: **RUSTSEC-2026-0186 memmap2 0.9.10 unsound** — Unchecked pointer offset in a `memmap2` internal helper, reachable only via `Mmap::offset`-family calls. Path: `tract-onnx` → `provcheck-{watermark, audioseal, wavmark}`. Documented reason for toleration: tract-onnx uses memmap2 for NNEF-serialised model files, but our audio detectors compile ONNX weights in via `include_bytes!` and hand tract a `&[u8]` slice, so the raw-mmap offset-manipulation path is never exercised at runtime. No fixed memmap2 version shipped upstream; row drops entirely once the audio detectors follow the image decoder's v0.7 phase 7b-followup migration off tract onto ort. Adds a fifth row to the Workspace section of SECURITY.md. Doc-only commit. Also confirms per SECURITY.md's update process: (a) the tauri app's GTK3 tail (10 unmaintained advisories from `gtk-rs 0.18` + the `selectors` sub-tail) is unchanged, still one-fix-away from Tauri's gtk4 backend migration; (b) no tolerated ID cleared this pass. |
| **v0.9.84** | 2026-06-30 | **comfyui-node README status header + kit lock/unlock comment block.** Two small operator-visible doc-staleness fixes. (1) `python/comfyui-node/README.md` Status header said `Status (v0.9.77): Fully wired for both image and audio.` — three iterations stale; v0.9.80 added example workflows + workflows README + sign-with-default-180s-timeout `stamp_signed_image.json`. Bumped header to `Status (v0.9.84)` and folded in the example-workflows + pytest + CI lines so anyone reading the comfyui-node README via PyPI / GitHub sees the v0.9.84 scope, not the v0.9.77 snapshot. (2) `crates/provcheck-kit/src/commands/mod.rs` lock/unlock module comment said `v0.3.0 has no daemon: each kit invocation is a fresh process ... print an honest "no-op for v1"` — both phrases were misleading (still no daemon at v0.9.84; "no-op for v1" reads as if v1 was the daemon-shipping target when it isn't). Dropped the version anchors entirely; the comment now describes the current state without anchoring to a release. (3) Verified `provcheck-examples/Cargo.toml` already has `publish = false` (item 5 from the audit menu, no action needed). (4) Verified the actual lock/unlock runtime `println!` strings are already version-anchor-free (item 4, no action needed). Doc-only commit + 1 comment edit; no behavioural change. |
| **v0.9.83** | 2026-06-30 | **sbom.md + atproto-signing-key.md version-anchor cleanup.** (1) sbom.md used `provcheck-v0.3.5` as the example filename throughout — 12 occurrences across the OWASP DT, Trivy, Grype, jq one-liners, sha256sum verify, and the local-reproduce script invocation. Any operator copy-pasting these would end up with command lines that don't match any tag they actually have. Replaced all 12 with `provcheck-vX.Y.Z` (placeholder). Also added "(`vX.Y.0` only — iteration tags do NOT ship release artefacts)" to the "what we ship" paragraph so consumers don't search for SBOMs under iteration tags. Updated "Sigstore + SLSA L3 is on the roadmap but not in v0.3.x" → v0.9.x (still accurate; we don't sign SBOMs at v0.9.x either). (2) atproto-signing-key.md's status line said "Status: v0.3 (provcheck v0.3.0). The wire format is stable; future revisions will preserve backward compatibility unless explicitly noted." Rewrote to "Status: wire format stable since provcheck v0.3.0" + cross-link to public-api-stability.md + semver-policy.md + concrete field-addition vs field-removal policy. This makes the wire-format contract auditable against the v1.0 release docs trio. Doc-only commit. |
| **v0.9.82** | 2026-06-30 | **about.md second sweep — Dockerfile version pin, watermark-detection trust-model paragraph, architecture diagram.** (1) `Render pipelines (Docker)` example Dockerfile hardcoded `ARG PROVCHECK_VERSION=v0.3.6` — that tag is from June 2026 and any operator copy-pasting the example would pull a pre-watermark-defaults-change release. Replaced with `vX.Y.0` placeholder + a paragraph explaining why we pin (e.g. the v0.5.2 SDR-default change can shift watermark parameters under you) and linking to the Releases page. (2) `What a watermark detection means` trust-model paragraph was silentcipher-only: "Audio bytes carry a recognised brand-stamp ... silentcipher's payload includes a brand identifier ... we recommend treating <50% as ambiguous." Rewrote to enumerate all six detector families (silentcipher / AudioSeal / WavMark on audio, TrustMark-B on images, per-frame TrustMark + temporal vote on video, SynthID-text on text), reference the canonical `provcheck::confidence` thresholds explicitly (Detected ≥ 0.70, Degraded ∈ [0.50, 0.70), NotDetected < 0.50), and note that audio + image marks survive lossy re-encoding. (3) Architecture-mental-model ASCII diagram showed "silentcipher decode + classifier" as the watermark layer — replaced with the full six-family list so a reader scanning the diagram sees the actual fan-out, not a v0.3-era snapshot. Doc-only commit. |
| **v0.9.81** | 2026-06-30 | **about.md + creator-workflow.md user-facing accuracy sweep.** Two of the most operator-visible docs in the repo were carrying stale claims that misrepresented what provcheck actually does in v0.9. **about.md**: (1) The "three orthogonal claims" section said "Neural watermark (silentcipher today; AudioSeal + WavMark slots scaffolded)" — but AudioSeal has been live since v0.4, WavMark since v0.5, plus image/video TrustMark + SynthID-text landed in v0.7 → v0.9. Rewrote as "Six detector families ship live in v0.9: silentcipher + AudioSeal + WavMark on audio, TrustMark-B on images, per-frame TrustMark + temporal majority-vote on video, and Bayesian tournament-sampling z-score for SynthID-text on text." (2) The verifier walkthrough output showed `audioseal: n/a (implementation pending — see crate docs)` and `wavmark: n/a (implementation pending — see crate docs)` — those messages have not been emitted since the v0.4/v0.5 detector wirings landed. Updated example to show `not detected` (the actual emitted form). Surrounding paragraph rewritten to enumerate all six detectors. (3) Differentiation table cell said "yes (silentcipher live; more scaffolded)" — replaced with the full six-family list so anyone scanning the differentiation table sees provcheck's actual scope, not a v0.3-era snapshot. **creator-workflow.md**: (1) `kit serve` section said "Cold-start tract optimisation runs once" — we switched to ort in v0.7 phase 7b-followup; the cold-start is now `ort` session setup. (2) CUDA section said "The default download stays a single tract-only CPU binary" — replaced with accurate text describing the `ort` bundled CPU backend (platform-specific `onnxruntime` shared lib ships in the release archive). Doc-only commit, no behavioural change. |
| **v0.9.80** | 2026-06-30 | **ComfyUI example workflows land — closes the v0.9-roadmap §9c "ships example workflows" promise.** §9c said "v0.9 wires the actual subprocess call to provcheck-kit stamp, handles tensor save / load, **and ships example workflows**." The first two landed in v0.9.0 + v0.9.77; the third did not. v0.9.80 ships three minimal ComfyUI workflow JSON files under `python/comfyui-node/workflows/`: (1) `stamp_image_minimal.json` — `LoadImage` → `ProvcheckStamp` → `PreviewImage` (smallest possible image-stamp graph; placeholder `example.png` input). (2) `stamp_audio_minimal.json` — `LoadAudio` → `ProvcheckStampAudio` → `SaveAudio` (audio equivalent; SaveAudio writes the stamped WAV to ComfyUI's output dir). (3) `stamp_signed_image.json` — `LoadImage` → `ProvcheckStamp(sign=True, timeout=180s)` → `SaveImage` (demonstrates the v0.9.77 `sign` opt-in with a documented 180s timeout to cover the extra time signing adds; requires `provcheck-kit init` upstream; sign failure → fail-closed passthrough). All three target ComfyUI's `version: 0.4` workflow schema (current as of ComfyUI 0.3.x). Workflows README explains drag-and-drop loading, what console output to expect, how to swap placeholder inputs, and how to debug the three most common "this doesn't seem to work" failure modes (kit not on PATH, upstream Load node failure, missing identity for sign=True). v0.9-roadmap §9c updated with per-version SHIPPED markers tracing v0.9.0 → v0.9.77 → v0.9.80. Workspace clippy clean (Python-only commit; pre-push hook is the only cargo). |
| **v0.9.79** | 2026-06-30 | **Three more stale-version-anchor cleanups in kit + SECURITY.md tolerated-advisories row.** (1) `provcheck-kit::commands` module-level doc-comment said `lock`/`unlock` print "no-op for v0.3.0"; v0.9.64 updated the actual strings but not the doc-comment. Dropped the version anchor from the doc. (2) The bail message in the software-keypair-init arm for Yubikey-backed identities said "wait for v0.5.0 P2" — but v0.5.0 P2 shipped long ago and the Yubikey path now exists via a separate code path. The arm is logically unreachable per its own comment ("exists so the compiler keeps every match exhaustive"). Updated the message to describe the actual failure mode if the arm DOES execute (internal dispatch bug, file an issue). (3) `kit init --backend yubikey` printed "Detected Yubikey serial N. v0.5.0 generates the key on PIV slot 0x9c..." — the v0.5.0 anchor was confusing on v0.9.x. Rewrote as "The key will be generated on PIV slot 0x9c..." with no version anchor. (4) SECURITY.md RUSTSEC-2024-0436 row note refined to call out that the image decoder migrated off `tract` in v0.7 phase 7b-followup but `tract` is still in the lockfile transitively; row drops when `tract` exits the lockfile entirely. Source-only commit, no behavioural change. |
| **v0.9.78** | 2026-06-30 | **SECURITY.md threat-model accuracy fix — detectors run on `ort`, not `tract`; weights are SHA-pinned DLC, not `include_bytes!` blobs.** SECURITY.md's "Scope" section described the watermark-detector threat model with two factually-stale claims that could mislead a security reviewer: (1) "pure-Rust ONNX inference via `tract-onnx`" — but v0.7 phase 7b-followup migrated the image decoder to `ort` 1.20 (onnxruntime with the `load-dynamic` feature; platform-specific CPU shared lib bundled in the release archive), and (2) "ONNX files embedded into the binary at compile time (`include_bytes!`)" — but v0.8 phase 8a moved detector weights to download-on-demand DLC delivery, which is what dropped the kit binary from ~143 MB to ~22 MB. **Updated text accurately describes**: ort backend; the DLC delivery flow (compile-time MANIFEST table → first-call cache lookup → on-demand operator-consented install via `provcheck-kit weights install` → SHA256 verification before atomic rename into cache → re-hash on every subsequent load); and the model-substitution attack surface (binary-integrity covers the MANIFEST; SHA-256 collision covers the weight file — DLC delivery does NOT introduce a new substitution surface beyond what the binary's integrity story already covers). Also updated the RUSTSEC-2024-0436 tolerated-advisories row to note that `tract` is still pulled in transitively even though the image decoder migrated off it; the row drops when `tract` exits the workspace lockfile entirely. Doc-only commit, no cargo runtime cost beyond the pre-push hook. |
| **v0.9.77** | 2026-06-30 | **ComfyUI node — audio variant lands, sign opt-in lands, configurable timeout lands.** Three real gaps in `python/comfyui-node` closed in one batch. **(1) StampAudioNode**: the README claimed an "audio variant ... routed through silentcipher / AudioSeal" but no code existed. v0.9.77 lands the actual `StampAudioNode` Python class (FOSS Apache-2.0). Accepts ComfyUI's `AUDIO` dict (`{"waveform": tensor[B, C, samples], "sample_rate": int}`), serialises each batch element to a temp 16-bit PCM WAV via stdlib `wave` module + numpy (no new deps), shells through `provcheck-kit stamp <tmp.wav>` (auto-routes to silentcipher per the kit's modality detect), reads stamped WAV back, returns AUDIO dict. Same fail-closed posture as the image node: missing kit OR per-clip failure → passthrough with console warning, render queue never crashes. Handles malformed AUDIO inputs (not-a-dict, missing-waveform-key, weird shape) by passing through. Preserves `sample_rate` through the round trip. **(2) `sign` opt-in**: both nodes now accept an optional `sign: BOOLEAN` input (default `False`). When `False`, kit gets `--no-sign` (watermark only). When `True`, kit attempts to sign with the local identity; kit failure → passthrough with clear console message. Documented contract: signing requires `kit init` to have been run upstream. **(3) `timeout_secs` knob**: both nodes accept an optional `INT` input (default 120, range 5–600) clamped server-side. Slow hosts running CPU-only TrustMark embed can extend the per-frame timeout; fast hosts can shorten it. **+18 new pytest tests** (image node 5 → 9, audio node 0 → 13, total 22): sign argv-shape pins (default off passes `--no-sign`; True omits it), timeout clamping (99999 → 600, 0 → 5, 60 → 60), WAV round-trip mono + stereo within int16 precision (max error < 5e-4), WAV clipping on out-of-range float input, malformed AUDIO dict passthrough, sample-rate preservation, node-mapping registration includes both. Web extension applies branding to both nodes. New `.github/workflows/comfyui-node.yml` runs pytest on push for Python 3.10 + 3.12. Bumped `pyproject.toml` from 0.1.0 → 0.2.0 (minor: backwards-compat additions per semver-policy.md). Workflow file is doc-paths-filtered so it only fires on `python/comfyui-node/**` changes. |
| **v0.9.76** | 2026-06-30 | **v0.9-roadmap §9a + §9b updated to reflect shipped reality.** The roadmap doc still described §9a as "no-op stub today" and §9b's crate as `provcheck-stream-deepfake` (the planned name; the shipped crate is `provcheck-stream-detect`). Updated both sections with per-version SHIPPED markers tracing what landed in which iteration tag (§9a: v0.9.71 crate + v0.9.72 Report.detections + v0.9.73 CLI flag; §9b: v0.9.74 audio + v0.9.75 video). Documented the rationale for the final crate name (drops "deepfake" since the trait works for any AI-content detector, not just deepfake-specific ones). Flagged "GUI surface for live monitoring" (microphone / screen capture / RTSP feed) as ⏳ deferred to v1.x — the library API IS the v0.9 deliverable; desktop-app GUI integration sits in front of the existing Tauri surface and is a separate wiring task. Doc-only commit, no cargo cycles. The roadmap now matches the source tree, so anyone reading either gets the same status. |
| **v0.9.75** | 2026-06-30 | **Video half of `provcheck-stream-detect` lands — v0.9-roadmap §9b "frame batch feeder for video" is now real code.** v0.9.74 landed the audio half (PCM chunk feeder); v0.9.75 closes the video half promised in the same roadmap section. **New types**: `VideoStreamConfig` (window_frames + hop_frames + history_capacity, validated via `new`), `VideoFrame` (pts_secs + opaque encoded bytes — raw RGB / PNG / JPEG / whatever the detector expects), `VideoStreamingPipeline` (owned by intake thread, irregular-PTS frames buffered into fixed-frame-count windows). **Wire format**: when a window completes, the pipeline concatenates frames with a 4-byte big-endian length prefix per frame, so the detector implementor can re-parse boundaries without an extra alloc. Window timestamps derive from the first and last frame's `pts_secs` in the window. **+14 new tests** (was 19, now 33): VideoStreamConfig validation × 5 (zero window / zero hop / hop > window / hop == window / overlapping hop), pipeline no-detector buffering, per-window-per-detector emission count (3 windows × 2 detectors = 6 verdicts), hop-based buffer advance (window=5 hop=2, 10 frames → 3 windows), pts → window timestamp math (window_frames=3, frame interval 0.1s → window 1 = 0.0-0.2s, window 2 = 0.3-0.5s), history-capacity bound with FIFO eviction, drain clears state, Send+Sync, Debug includes state, length-prefix wire format pin (deterministic concat layout). Workspace clippy clean under `--jobs 8 --test-threads=8` policy; single-crate target, never overlapping cargo invocations. |
| **v0.9.74** | 2026-06-30 | **`provcheck-stream-detect` crate lands — v0.9-roadmap §9b "streaming deepfake detection" is now real code.** v0.9.71-73 closed the §9a "detection slot architecture" promise; v0.9.74 closes §9b "streaming intake pipeline" with a real crate. **New crate** (`crates/provcheck-stream-detect/`, FOSS Apache-2.0, ships no model weights, `#![forbid(unsafe_code)]`): `AudioStreamConfig` (sample_rate + window_samples + hop_samples + history_capacity, validated via `new` with operator-facing errors on zero / hop > window cases), `AudioStreamingPipeline` (owned by intake thread, holds `DetectorRegistry` + ring buffer + verdict history deque), `WindowedVerdict` (timestamped `DetectionResult` with start_secs + end_secs so consumers can plot confidence over time), `StreamError` (`InvalidConfig` + `NoDetectorRegistered`). Pipeline contract: operator feeds f32 PCM samples via `feed`, pipeline buffers into windows, emits a verdict per (window × registered detector) into bounded history deque, operator drains via `drain_verdicts` or peeks via `latest_verdict`. No look-ahead, no padding — strict window-emits-when-buffer-full semantics. Bounded history per `history_capacity` (FIFO eviction). +19 unit tests covering config validation (5: zero rate / zero window / zero hop / hop > window / hop == window), config helpers (window_duration_secs), no-detector buffering invariant, per-window-per-detector emission count (3 windows × 2 detectors = 6 verdicts), hop-based buffer advance (250 samples with window=100 hop=50 → 4 verdicts), chronological start time monotonicity, sample-position-to-timestamp math at 16 kHz, bounded history with FIFO eviction, drain clears state, latest_verdict returns most-recent, overlapping windows emit independent verdicts (window=100 hop=50 → 50% overlap, 200 samples → 3 windows), Send+Sync, Debug includes state, WindowedVerdict serde round-trip. Workspace clippy clean, crate built under new `--jobs 8 --test-threads 8` CPU-cap policy. |
| **v0.9.73** | 2026-06-30 | **`provcheck --detect ai` CLI flag — the v0.9-roadmap §9a promise is now real on the binary surface.** v0.9.71 + v0.9.72 landed the `provcheck-detect` crate and wired `Report::detections` through the verifier. v0.9.73 closes the loop: the `provcheck` CLI now accepts `--detect ai` (clap value-enum) and on each verify call constructs a `provcheck_detect::DetectorRegistry`, reads the file once, runs `run_all` over every registered detector, and pushes results into `report.detections`. The FOSS core ships with ZERO detectors registered — without an operator-supplied detector pack the flag is a documented no-op (the report's detections vec stays empty). The flag exists so operator scripts that ARE wired against a paid DLC pack (Creative Mayhem-distributed after v1.0) or an operator-supplied open-source third-party detector can request the detection pass via a stable flag without rewriting the rest of the command line each release. Help text describes the bring-your-own-model story so anyone reading `provcheck --help` understands the flag's contract. **+4 new integration tests** (cli exit-codes 15 → 19): `--detect` appears in `--help`, unknown value (`--detect bogus`) exits 2 with clap value-enum error, missing file with `--detect ai` still routes to exit 2 (flag doesn't change exit-code behaviour for unrelated failures), help text is descriptive. Added `provcheck-detect` to provcheck-cli's Cargo.toml. The doc-trio (public-api-stability + semver + release-process) + provcheck-detect crate + Report.detections field + `--detect ai` flag together complete the v0.9-roadmap §9a "Detection slot architecture" promise that had sat as documentation since June. Workspace clippy clean. |
| **v0.9.72** | 2026-06-30 | **`Report::detections` field wired through — `provcheck-detect` is now load-bearing in the verifier, not freestanding.** v0.9.71 landed the `provcheck-detect` crate with a `Detector` trait + `DetectorRegistry` dispatch + result types. But without a slot in `Report`, no downstream consumer (CLI `--json` mode, GUI, kit) could surface a detection result. **Wiring**: `provcheck::Report` now carries `pub detections: Vec<provcheck_detect::DetectionResult>` alongside `watermarks`. The core `verify_with_options` path leaves it empty (the verifier doesn't bundle any detector); callers (CLI / GUI / kit / a downstream library) populate it by running their own `DetectorRegistry::run_all` and pushing the results. Doc-comment on the field makes the distinction explicit: watermark detectors find marks the producer deliberately embedded; AI-content detectors classify content that may not carry any watermark. Cross-references the bring-your-own-model story (commercial paid DLC OR operator-supplied open-source via the public trait). Added `provcheck-detect` to `provcheck`'s dep set. +3 new tests pin the serde shape: `skip_serializing_if = "Vec::is_empty"` omission, populated detections serialise under the `detections` key with the family snake_case form, **backward-compat deserialise of legacy Report JSON without a `detections` field** (uses `#[serde(default)]` to populate as empty vec). All four Report constructors across `lib.rs` / `verification.rs` / `report.rs` tests updated in lock-step. Workspace clippy clean. |
| **v0.9.71** | 2026-06-30 | **`provcheck-detect` crate lands — Detector trait is now real code, not just doc promises.** v0.9.70's public-API-stability doc promised a `Detector` trait + bring-your-own-model contract for AI-content detection, but the actual `provcheck-detect` crate did not exist. The v0.9-roadmap had described it in 9a since June but never materialised. **New crate** (`crates/provcheck-detect/`, FOSS Apache-2.0, ships no model weights): `Detector` trait (`Send + Sync`, object-safe so `Vec<Box<dyn Detector>>` works, lazy-load discipline documented), `DetectionFamily { Audio, Image, Video, Text }`, `DetectionStatus { Detected, Degraded, NotDetected, NotApplicable, Error }` (mirrors `WatermarkStatus` tier semantics so renderers can treat watermark + AI-detection results uniformly), `DetectionResult` (serde wire format, `skip_serializing_if = "Option::is_none"` for optional fields), `DetectorError { ModelNotInstalled, Inference, Io }` (each carries the detector name so the dispatch layer can route them). `DetectorRegistry` is the dispatch layer that holds `Vec<Box<dyn Detector>>` and provides `register` + `run_all` (errors project onto `DetectionResult { status: Error, ... }` so the dispatch never short-circuits). +15 tests covering serde wire format, snake_case rename pins, None-field omission, round-trip, Error display invariants, registration order preservation, error-projection in the dispatch layer, object-safety, Send+Sync, Debug includes detector names. Added to workspace members + the v1_release_docs.rs publishable-crates completeness check (which now requires 15 crates including detect). The trait is the v1.0 plumbing contract for both the future commercial-detector paid-DLC packs and operator-supplied open-source third-party detectors. Workspace clippy clean. |
| **v0.9.70** | 2026-06-30 | **Pre-v1.0 task #155 docs trio lands + deepfake-detection framing fix.** Three new release-contract docs in `docs/`: `public-api-stability.md` (the v1.0 stability matrix per crate; what semver covers; CLI binary surface + exit codes; what we will NOT do; crates we publish to crates.io), `semver-policy.md` (versioning rules; MSRV bump policy; wire-format change categories; patch-release scope; yanking criteria), `release-process.md` (mechanical checklist for every `vX.Y.0` tag: workspace builds clean → tests pass → cargo audit clean → README changelog row → three-file version bump → SBOMs → clean-machine verify → public-API check → tag → matrix → crates.io publish in dependency order → public-mirror sync → post-release memory note + rollback rules). New integration test `crates/provcheck/tests/v1_release_docs.rs` (+9 tests) pins doc existence, sibling cross-links between all three docs (catches a future file rename that breaks navigation), the v*.*.0 release-matrix glob reference, the MSRV bump time window, and the publishable-crates list completeness invariant. **Deepfake-detection framing fix**: external review correctly flagged that v0.7-era copy could read as if deepfake detection ships free in the FOSS core. It does NOT. Watermark detectors (TrustMark image/video, silentcipher/AudioSeal/WavMark audio, SynthID-text text) DO ship FOSS — they detect content that was deliberately marked at generation time. Deepfake detection (does this content come from an AI even WITHOUT a watermark?) is bring-your-own-model: commercial detector packs ship as paid DLC after v1.0 (Creative Mayhem distribution), OR operators wire their own open-source third-party detector via the FOSS `Detector` trait. provcheck does not bundle ANY deepfake detector model in either the FOSS core or the paid DLC layer — only the plumbing. Updated v0.9-roadmap section 9b + README Status section to make the distinction explicit. Memory rule `feedback_no_commercial_models_in_repo` added to lock the policy across future sessions. Workspace clippy clean. |
| **v0.9.69** | 2026-06-30 | **Pre-v1.0 TrustMark runtime-error message — drop stale tract-backend status, ship ort reality + recovery action.** Every runtime error from the TrustMark image decoder used to surface the message "v0.7 phase 7b status: preprocessing + DLC weight delivery + verifier integration are wired, but tract 0.21's ONNX op coverage cannot run Adobe's decoder export... 7b-followup switches the backend to ort." The 7b-followup landed long ago (per `provcheck-image::model` docs) and we ship ort 1.20 — operators hitting a runtime error were reading a status report from the v0.7 era describing a past problem with a past backend, not actionable guidance. **New message**: names the actual ort backend, describes what the detector loads (the BCH-5 decoder ONNX on a 256x256 RGB tensor normalised to [-1, 1]), and gives the operator a concrete recovery action (`provcheck-kit weights uninstall trustmark && provcheck-kit weights install trustmark` to re-fetch corrupt cached weights). **Regression pins** (+2 tests): source-walking test that fails if a future maintainer reintroduces the prior-backend name + version, or the "7b-followup switches the backend" promise (sentinel strings built via char-by-char concatenation so the test source itself doesn't match). Positive check: replacement message names "via ort" + the recovery command. Workspace clippy clean, image now at 86 tests. |
| **v0.9.68** | 2026-06-30 | **Pre-v1.0 SynthID-text detection-result message — drop "follow-up item" stale promise on the hot path.** Every successful SynthID-text detection used to end the operator-facing result message with "Default word-level tokenizer; HF subword tokenizer support for higher accuracy against real LLM output is a follow-up item." This was a known-incomplete-feature notice baked into the hot path — every detection report read "this isn't finished" rather than describing what the detector actually did. The word-level tokenizer is itself a legitimate, complete detection scheme (whitespace-split + lowercase + punctuation-strip; pinned via the 14 v0.9.32 tokenize/erf/Φ/classify tests) — it's not a partial implementation. Replaced the message with a positive description: `"Word-level tokenizer (whitespace-split, lowercase, punctuation-stripped)."` **Regression pins** (+2 tests): source-walking test that fails if a future maintainer reintroduces a "is a follow-up item" sentinel anywhere in the crate (builds the stale string by concatenation so it doesn't match its own source), and a positive check that the replacement message stays positively-worded. Operators running detection now see what the tool DID, not what it might-eventually-do. Workspace clippy clean, synthid-text now at 21 tests. |
| **v0.9.67** | 2026-06-30 | **Pre-v1.0 end-to-end coverage for v0.9.66's X25519 import-backup path.** Adds 3 new integration tests to `crates/provcheck-kit/tests/smoke.rs` (was 6, now 9): `import_backup_identity_file_flag_appears_in_help` — pins the new `--identity-file <PATH>` flag shows up in `kit import-backup --help` with X25519/recipients context, so a future maintainer can't accidentally drop it. `import_backup_identity_file_with_missing_file_exits_nonzero` — operator hands a non-existent identity path → non-zero exit with operator-readable diagnostic (not a panic). `export_then_import_x25519_round_trip_via_library_apis` — exercises the library export → string-format identity (matches the CLI's line-scan path) → from_str parse → import_with_x25519_identity round-trip end-to-end, confirming fingerprint + chain_pem preservation. Together with the existing library-level `x25519_round_trip_preserves_all_fields` test, the X25519 recovery-recipient backup story is now covered both inside-out (library) and outside-in (CLI dispatch). Workspace clippy clean, kit lib + smoke tests all green. |
| **v0.9.66** | 2026-06-30 | **Pre-v1.0 `kit import-backup --identity-file` — wire X25519-recipient restore through CLI (real feature gap closed).** Before v0.9.66 a creator who exported a backup with `kit export-backup --use-recovery-recipients` (the X25519-encrypted path that recovery recipients hold a share of) had no way to restore it via the CLI — `kit import-backup` only handled passphrase-encrypted bundles. The library has had `provcheck_sign::backup::import_with_x25519_identity` since v0.4; only the kit-level surface was missing, and the kit doc-comment correctly described this as a follow-up. **Implementation**: new `--identity-file <PATH>` flag on `kit import-backup`, accepts an age X25519 identity file in rage-keygen format (scans line-by-line for the first `AGE-SECRET-KEY-1…` line; multi-identity files explicitly not supported and surfaced as a clean error), constructs `age::x25519::Identity` and calls the existing library entry point. Default (no `--identity-file`) still takes a passphrase, matching the default `export-backup` mode. Added `age = "0.11"` to provcheck-kit `Cargo.toml`, matching the version pinned by provcheck-sign so the recipient/identity types interop. Module-level doc updated to reflect the new symmetry between export and import paths. Recovery-recipient backups now have a real restore story — one more "deferred follow-up" cleared for v1.0. Workspace clippy clean, 68 kit lib tests + 6 integration tests passing. |
| **v0.9.65** | 2026-06-30 | **Pre-v1.0 stale "(pending) / currently empty" fixtures-README cleanup.** The `crates/provcheck/tests/fixtures/README.md` file claimed the integration test suite at `../integration.rs` was "(pending)" and that fixture population was "the first task of milestone 2". Reality: `integration.rs` has had 13 tests since v0.5.x covering all four documented outcome categories (verify, unsigned, tampered, non-media) via run-time-synthesised fixtures (silent WAVs via `hound` + ES256 chains via `rcgen`) — there are no checked-in binaries because none were ever needed. Rewrote the README to reflect what the suite actually does, document the synthesis approach, and replace the "deferred until milestone 1 actually needs them" hand-wave with a concrete decision matrix for if/when a real binary fixture is ever justified (under 200 KB commit, 200 KB to 2 MB committed with justification, over 2 MB → release-asset SHA-pinned download via the `provcheck-weights` pattern). The previous text would have read as a serious incomplete-feature gap to any operator scanning the test surface for confidence. Workspace clippy clean, no code changes. |
| **v0.9.64** | 2026-06-30 | **Pre-v1.0 stale "lands in v0.5.x" user-facing message cleanup.** Three operator-facing kit messages still promised features by specific landed-in versions that long since shipped past their target without delivering: `kit lock` / `kit unlock` no-op messages cited "v0.3.0" (we're at v0.9.x), the yubikey factory-key error message pointed users at `kit import-yubikey (lands in v0.5.1)` which never landed (replaced with the actual ykman workaround), and `kit rotate` for yubikey-backed identities cited `(lands in v0.5.0 P3)` which never landed (replaced with the documented init-new-slot + revoke-old workaround). **Regression pin**: added a source-walking test (`deferred_message_source_does_not_promise_landed_version`) that fails if any future maintainer reintroduces a `lands in v0.X.Y` style sentinel. The test builds the stale tokens via string concatenation so it doesn't match itself. +3 new kit tests. Operator-facing messages now describe the workaround, not promise a version that may never ship. Workspace clippy clean. |
| **v0.9.63** | 2026-06-30 | **Pre-v1.0 wavmark stereo embed dispatch — real feature gap closed.** Switching from invariant-pinning to actual incompleteness hunting per the "not genuinely feature complete" directive. **Feature work**: the kit dispatcher's wavmark embed path used to hard-bail with `bail!("--channels stereo is not yet supported for --kind wavmark")` even though `wm_encode::embed_stereo` + `wm_audio::decode_to_stereo_16k` had existed in the library since v0.7. The bail is now replaced with a working stereo path that mirrors the audioseal dispatch byte-for-byte: full stereo decode, channel-mode resolution via the existing `resolve_output_channels` helper, two-channel `embed_stereo` when out_channels==2, downmix-then-mono-embed otherwise, stereo WAV output. **+4 new wavmark unit tests** (was 43, now 47): embed_stereo mismatched lengths error path, embed_stereo empty input propagates Empty, embed_with_config parity wrapper routes through, embed_stereo_with_config parity wrapper routes through (catches a future maintainer who silently drops a wrapper into a stub). One genuine "not yet supported" surface area closed for v1.0. Workspace clippy clean. |
| **v0.9.62** | 2026-06-30 | **Pre-v1.0 WavMark aggregate_lower_payload + matches_fix_pattern boundary coverage pass.** Adds 7 new unit tests for `provcheck-wavmark::detect` (was 8, now 15). aggregate_lower_payload × 5: all-zero bits → 0x0000, all-1.0 bits → 0xFFFF, MSB-first bit-0 of byte 0 lands at 0x80,0x00 (pinning the byte/bit-index math), averages across multiple hits (2 hits at 0.4 + 0.6 → avg 0.5 → bit set), sub-threshold average doesn't set bit. matches_fix_pattern × 2: inclusive ≥0.5 threshold pin (exactly 0.5 counts as 1 — catches a future tightening to `> 0.5` that would silently shift detection floor), bit just below 0.5 fails. The wavmark detection payload-aggregation math is the wire-format projection from probabilities to the 16-bit custom payload; pinning every boundary case catches a future maintainer's "off-by-epsilon" that would silently break payload recovery on marginal-SNR inputs. Workspace clippy clean. |
| **v0.9.61** | 2026-06-30 | **Pre-v1.0 silentcipher detect file-path coverage pass.** Adds 5 new unit tests for `provcheck-watermark::detect` — the operator-facing file-based entrypoint. Detect on non-audio returns WatermarkKind::SilentCipher (the dispatch contract — every NotDetected result carries the correct kind, not generic Unknown). No-extension file → not audio (the looks_like_audio gate's no-extension branch). Text extension `.txt` → not audio. PDF extension `.pdf` → not audio. Zero-confidence invariant: every not_detected path produces confidence == 0.0 exactly (NOT the 0.5 "no result" sentinel some Python ports use — pinned to catch a port that might confuse the two). The detect entrypoint is the verifier's first cliff for every audio asset; pinning the not-detected paths prevents a silent regression that would surface generic Unknown kind or non-zero confidence on rejected inputs. Workspace clippy clean. |
| **v0.9.60** | 2026-06-30 | **Pre-v1.0 verification.rs unit-test coverage pass (module from 0 → 10 tests).** Adds 10 new unit tests for `provcheck::verification` — the module had ZERO direct test coverage despite being the verifier's main entry point. VerifyOptions::default × 2: no trust_store_pem, require_trusted=false (the website's FAQ documents this contract — silent flip would change every exit code on signed-but-not-trust-anchored content). is_identity_label × 5: accepts bare label, accepts `__` disambiguator suffix (c2pa-rs decoration on hash collisions), accepts `.` suffix variant, rejects unrelated labels, rejects prefix-match-without-separator (strict separator contract — `app.provcheck.identityXX` must NOT match), rejects substring inside (not as prefix). verify() error paths × 2: missing file returns Io, invalid trust-store PEM returns InvalidTrustStore. The verification module's identity-label matcher is load-bearing for every signed asset's report; pinning catches a future maintainer who removes a separator-acceptance branch. Workspace clippy clean. |
| **v0.9.59** | 2026-06-30 | **Pre-v1.0 ALLOWED_ALGORITHMS string-level invariant coverage pass.** Adds 5 new unit tests for `provcheck-attestation-spec::ALLOWED_ALGORITHMS` (was 12 identity-claim-and-constants tests, now 17). String uniqueness invariant (duplicates would signal a manifest-edit bug). Each entry has at least one uppercase letter (catches a future lowercase typo). 5 ≤ alg.len() ≤ 8 (the JOSE header `alg` value bounds; catches both a too-short typo like "ES" and a too-long mistake like "ES256-PSS-SHA256-LONG"). Ed25519 canonical-case pin: only "Ed25519" appears, NOT "ED25519" or "ed25519" (the JOSE convention). EdDSA generic family name explicitly excluded (our spec requires Ed25519 for curve specification; a future maintainer who adds "EdDSA" would break c2pa-rs interop). These pins protect the wire-format alg-name contract that publishers + verifiers both substring-match against. Workspace clippy clean. |
| **v0.9.58** | 2026-06-30 | **Pre-v1.0 waveform_to_spectrum + IstftStreamer error-path coverage pass.** Adds 8 new unit tests for `provcheck-watermark::stft` (was 128, now 136 lib tests). waveform_to_spectrum empty input → StftError::Empty. spectrum_to_waveform with zero-frame Spectrum → StftError::TooShort. IstftStreamer::new with n_frames=0 errors (the streaming constructor's input-validation contract). n_samples_input on the returned Spectrum equals raw_len + (WIN - raw_len % WIN) — the always-pad-to-multiple-of-WIN invariant from the v0.5.0 silentcipher parity fix. n_frames matches compute_n_frames on the padded length (math consistency invariant). magnitude + phase buffers both have layout FREQ_BINS × n_frames (streaming iSTFT contract). magnitude is non-negative (sqrt invariant). phase is finite (atan2 contract). The forward STFT for the embed path is the load-bearing producer of the encoder's input; pinning these invariants prevents silent corruption of the embedder side. Workspace clippy clean. |
| **v0.9.57** | 2026-06-30 | **Pre-v1.0 map_xrpc_err substring-routing coverage pass.** Adds 8 new unit tests for `provcheck-publish::records::map_xrpc_err` — the bridge from atrium's generic XRPC `Error<E>` to our typed `RecordsError`. The function substring-matches on common patterns to surface meaningful CLI distinctions; pin each documented routing branch. `invalid_token` → Http with session hint (carries "session may have expired" + the inner message). `session` substring → Http. `expired` substring → Http. `invalid_request` → PdsRejected. `400` → PdsRejected. `conflict` (record-already-exists) → PdsRejected. Unknown messages → Http (default branch). Case-insensitive — `Invalid_Token` / `INVALID_TOKEN` / `invalid_token` all route the same (pinned so a future "strip lowercase" optimisation can't silently break mixed-case provider responses). The routing layer is the operator-facing diagnostic surface for every PDS interaction; silent drift here turns "session expired, re-run kit login" into a confusing 400 message. Workspace clippy clean. |
| **v0.9.56** | 2026-06-30 | **Pre-v1.0 extract_carrier_chunk column-slice coverage pass.** Adds 5 new unit tests for `provcheck-watermark::encode::extract_carrier_chunk` — the chunked-extract helper that lets the encoder iterate over long-form audio without materialising a full carrier copy (the v0.5.1 OOM fix's core primitive). Full range round-trip (t_start=0, chunk_t=t_frames → bit-identical to input). Output size invariant: exactly FREQ_BINS × chunk_t f32s across multiple (t_start, chunk_t) combinations — the layout contract the ONNX session asserts on. Per-bin value preservation: for each bin b, the chunk's row b equals the carrier's row b sliced at [t_start..t_start+chunk_t] (catches a future off-by-one in the column-slice math that would silently corrupt every chunked embed). First chunk starts at column 0 of each bin. Tail chunk reads the final chunk_t columns. The chunked-extract is the v0.5.1 OOM fix's load-bearing primitive; pinning its column math prevents a silent regression that would either corrupt the embed or reintroduce the 600 MB allocation. Workspace clippy clean. |
| **v0.9.55** | 2026-06-30 | **Pre-v1.0 DEFAULT_MESSAGE_SDR_DB + MESSAGE_BAND_SIZE constant coverage pass.** Adds 5 new unit tests for `provcheck-watermark::encode` (was 30, now 35). DEFAULT_MESSAGE_SDR_DB × 3: pinned to 30.0 (v0.5.2's codec-survival sweep value — silently bumping back to 47.0 the training default would lose the lossy-delivery fix), finite and positive, less than 47.0 training default invariant (catches a future drift back up to the inaudibility-optimised value). MESSAGE_BAND_SIZE × 2: pinned to 1024 (the encoder's `nn.Linear` output dim; bumping requires re-training and the debug_assert at line 578 fires loudly anyway, but pinning catches it at test time), strictly less than FREQ_BINS = 2049 (the encoder only modulates the low-frequency band; above MESSAGE_BAND_SIZE we zero-pad). Both constants are wire-format pins between the trained checkpoint and the running encoder; silent drift here corrupts every embed. Workspace clippy clean. |
| **v0.9.54** | 2026-06-30 | **Pre-v1.0 AAC priming constant + detect_from_mono empty-input coverage pass.** Adds 3 new unit tests for `provcheck-watermark`. AAC_DEFAULT_PRIMING_SAMPLES = 1024 pinned — the v0.5.3 hotfix value for public issue #24 (AAC-in-MP4/M4A returned conf 0.000 because every STFT frame was 1024 samples out of phase with the embedder's frame grid). Half-frame priming invariant explicitly documented: 1024 = 2048/2 (the 2048 full-frame ambiguity is exactly the trap that caused #24; pinning the half-frame value catches a future "simplification" that would silently regress). detect_from_mono_44k1 with empty waveform short-circuits via StftError::Empty → user-facing message contains "zero samples" (the operator's debugging clue for the "I handed in silence" case). An attempt at a "too-short waveform" companion test was tried and removed when 100 samples turned out not to trigger StftError::TooShort under the current pad+reflect math — keeping the test surface honest. Workspace clippy clean. |
| **v0.9.53** | 2026-06-30 | **Pre-v1.0 pack_partial_logits + silentcipher not_detected helper coverage pass.** Adds 5 new unit tests for `provcheck-watermark::lib` (was 110, now 115 lib tests). pack_partial_logits × 4: t_consumed=0 returns empty vec (the early-exit-before-min-frames path), full t_consumed round-trips bit-identically (no off-by-one in the column copy), partial t_consumed preserves only the first t_consumed columns per dim (the pack must NOT carry zero-suffix tail bleed into the partial decode), output length is exactly MESSAGE_DIM × t_consumed for any t_consumed (the layout contract decode_logits asserts on — wrong shape causes a confusing panic). not_detected helper × 1: sets WatermarkKind::SilentCipher (the silentcipher-specific kind), NotDetected status, zero confidence, all-None payload/brand/marked_regions, message preserved. pack_partial_logits drives the confidence-based early-exit path on long-form embed; pinning these invariants prevents a silent off-by-one that would corrupt every partial decode. Workspace clippy clean. |
| **v0.9.52** | 2026-06-30 | **Pre-v1.0 regions_from_tile_quality + threshold-pin coverage pass.** Adds 10 new unit tests for `provcheck-watermark::lib` (was 101, now 110 lib tests). regions_from_tile_quality × 6: empty input → empty regions, all-below-threshold → empty, short run below MIN_REGION_SECONDS filtered (~2-tile run = ~1.95s), long run above min reported (5 tiles = ~4.9s), unterminated run reaching tile_quality end is still reported (catches the "did we close the open span" loop end check), threshold is inclusive (`q >= TILE_QUALITY_THRESHOLD` not strict `>` — tiles AT threshold count as hot). Threshold constants × 4: TILE_QUALITY_THRESHOLD = 0.55 pinned, MIN_REGION_SECONDS = 2.0 pinned, EARLY_EXIT_THRESHOLD > 0.70 invariant (must exceed brand-classify Detected threshold so early-exit can't downgrade Detected to Degraded), EARLY_EXIT_MIN_FRAMES = MESSAGE_LEN × 4 (4 tiles of redundancy before per-position mode-vote is trustworthy). The marked_regions feature is the UI's "where in the audio is the watermark?" surface; pinning region computation prevents silent regressions in localisation. Workspace clippy clean. |
| **v0.9.51** | 2026-06-30 | **Pre-v1.0 sanity_check_pem direct coverage pass.** Adds 6 new unit tests for `provcheck::sanity_check_pem` — the early gate that prevents a malformed trust-store input from confusing c2pa's loader. Well-formed CERTIFICATE block accepted. No BEGIN marker → InvalidTrustStore with "BEGIN CERTIFICATE" in the message. No END marker → InvalidTrustStore with "END CERTIFICATE" in the message. Empty input → InvalidTrustStore. Chain with multiple cert blocks accepted (common for full-chain trust stores). Private-key-only input rejected (a PEM with no CERTIFICATE block is wrong for a trust store). The PEM check is the operator-facing first cliff for `--trust-store` failures; pinning every documented rejection path means the user-facing diagnostic messages can't silently drift. Workspace clippy clean. |
| **v0.9.50** | 2026-06-30 | **Pre-v1.0 parse_payload_hex edge-corner + whitespace coverage pass — 50th iteration tag.** Adds 5 new unit tests for `provcheck-kit::commands::embed::parse_payload_hex` (was 8, now 13). All-zeros payload (`0000000000`) round-trips. All-0xFF payload round-trips. Tabs (`\t`) and newlines (`\n`) tolerated as whitespace via `is_whitespace` — pinned for operator copy-paste from shell pipes (not just spaces). 9 chars (just below the strict 10-char length requirement) errors with "got 9" in the message. 11 chars (just above) errors with "got 11". **Milestone**: v0.9.50 marks the 50th iteration tag in the v0.9.x coverage push (v0.9.0 → v0.9.50). Cumulative across the line: ~330 new tests, every clippy clean, every release-matrix skipped via the `v*.*.0` gate, no advance to v1.0. Workspace continues to compound coverage one tag at a time per the "you don't advance until you're all green" + "iterate until we run out of x.x.XXXXXXX bytes" directives. |
| **v0.9.49** | 2026-06-30 | **Pre-v1.0 build_data_payload + image wire-format constants coverage pass.** Adds 9 new unit tests for `provcheck-image::encode` (was 75, now 84). build_data_payload × 5: length = DATA_LEN (61 bits), first 8 bits are PROVCHECK_RAW_MAGIC (0xA5 = 0b10100101) MSB-first — the magic byte classify_bch5 uses to distinguish our marks from random BCH-decode noise. Bits 8..13 carry the 5-bit brand id MSB-first. Bits 13..DATA_LEN are zero-padded (reserved). Brand id u8 input only consumes the low 5 bits — pinned so a future caller passing 0xFF doesn't silently overflow into the reserved tail. Wire-format constants × 4: PROVCHECK_RAW_MAGIC = 0xA5 pinned (bumping this breaks every existing marked image). VERSION_BCH5 = [0,0,0,1] pinned. PROTECTED_LEN = DATA_LEN + ECC_LEN self-consistency invariant. SHORTEN_PAD = bch::K - DATA_LEN self-consistency invariant. The TrustMark-B + BCH-5 wire format is the public-DLC image-modality contract; pinning every byte position catches a typo that would silently break image embed↔decode symmetry. Workspace clippy clean. |
| **v0.9.48** | 2026-06-30 | **Pre-v1.0 SessionError Display coverage pass + 731-test milestone.** Adds 7 new unit tests for `provcheck-publish::session::SessionError` Display impls (was 53, now 60). SessionExpired Display directs operator to `kit login` (the CLI exit-code-3 path's only debugging clue). LoginRejected includes inner message. Http includes inner. Io includes inner. `#[from]` impl from `std::io::Error` compiles + dispatches. Format error includes inner. InvalidIdentifier includes the offending input string. **Workspace milestone**: 731 lib tests passing across the 13 non-platform crates, +320 since the v0.9.x line began (started 411). Adding ~29 platform lib tests + integration tests puts the workspace north of 760 total. Workspace clippy clean. |
| **v0.9.47** | 2026-06-30 | **Pre-v1.0 normalise_fingerprint boundary coverage pass.** Adds 6 new unit tests for `provcheck-kit::commands::normalise_fingerprint` (was 7, now 13). Accepts exactly 8 chars (documented inclusive lower bound for "ambiguous but useful prefix match" — pinned so a future tightening can't silently break short-prefix lookups). Rejects 7 chars (just below min). Rejects 65 chars (just above max). Accepts exactly 64 chars (at max — the full sha256 length). Round-trips idempotently (normalised string fed back produces same output). Empty string is too-short (carries the "short" guidance to the operator). These boundary tests pin the inclusive `[8, 64]` interval so a future maintainer can't drift it without an explicit test update. Note: an earlier draft duplicated existing tests verbatim; the surviving v0.9.47 batch is the 6 genuinely-new boundary cases. Workspace clippy clean. |
| **v0.9.46** | 2026-06-30 | **Pre-v1.0 CLI exit-code extras + preflight coverage pass.** Adds 6 new integration tests to `provcheck-cli/tests/exit_codes.rs` (was 9, now 15). `-h` short-help exits 0 (operators muscle-memory `-h` not `--help`). Unknown flag exits 2 (clap parse error path). Help text prints to stdout not stderr (pinned so operators can `--help | less` without surprise). `--require-attested --did did:plc:abc <file>` passes preflight (the require-attested preflight message must NOT appear when --did alone is set — confirms the `bsky_handle || did || auto_identity` OR-gate). Same for `--bsky-handle` alone. `--json --help` still emits help text (`--help` always wins over `--json`). The CLI exit-code matrix is the contract every CI gate and pipeline failure mode depends on; pinning these prevents silent shifts in automation behavior. Workspace clippy clean. |
| **v0.9.45** | 2026-06-30 | **Pre-v1.0 weights MANIFEST URL + name invariant coverage pass.** Adds 5 new unit tests for `provcheck-weights::manifest` (was 8, now 13). All entries point at the SAME release tag (catches partial-upgrade drift where some weights bump while others lag, silently breaking model compatibility). Every filename includes the family name (catches a future rename that decouples cache path from family). Every URL is https not http (defence-in-depth: no plaintext download URL can slip in). Family + variant strings are non-empty. Family names use lowercase ASCII + hyphen + digit only (defensive: family names appear in CLI subcommand args, cache paths, and error messages — pinning the alphabet prevents a future mixed-case entry that breaks operator muscle memory). Combined with v0.9.44's lookup + hex tests, the MANIFEST contract is now exhaustively pinned for v1.0 — the public DLC URL + SHA + cache-path triplet that every detector hot path depends on. Workspace clippy clean. |
| **v0.9.44** | 2026-06-30 | **Pre-v1.0 weights entry-lookup + hex + manifest-presence coverage pass.** Adds 11 new unit tests for `provcheck-weights::lib` (was 17, now 28). Entry lookup × 6: silentcipher encoder + decoder both present (the audio detector hot path), audioseal detector + generator both present (variable name `generator` not `gen` since `gen` is a reserved keyword in edition 2024 — pinned for future maintainers), wavmark all 4 variants present (encoder/decoder/fc-weights/fc-back-weights), unknown family + known variant still errors, known family + unknown variant errors, error carries input strings verbatim (catches a future refactor that drops the context). `hex` helper × 3: empty input → empty string, lowercase-only output (mirrors hex_lower in attestation-spec), 2-char-per-byte invariant. WeightCacheState is Copy invariant (catches a future field that breaks API ergonomics). The manifest entries are the public-DLC URL + SHA contract; pinning every documented variant catches a silent removal that would break the first-run install flow. Workspace clippy clean. |
| **v0.9.43** | 2026-06-30 | **Pre-v1.0 effective_sample (zero-copy pad) coverage pass.** Adds 5 new unit tests for `provcheck-watermark::stft::effective_sample` — the inline-zero-copy pad replacement that dropped ~600 MB of memory pressure off the encode-side STFT on a 56-minute 44.1 kHz episode (v0.6.0 P3 phase 3a). Middle region returns the raw waveform value (the hot path). Head reflection mirrors around index 0 without duplicating waveform[0] — pinned with concrete numbers (`pad=3, n=5 → pos 0 = waveform[3]`, `pos 1 = waveform[2]`, etc.). Tail reflection mirrors around index n-1 without duplicating waveform[n-1] — pinned the same way (`pad+n → waveform[n-2]`). Out-of-band indices (`usize::MAX/2`) do NOT panic and produce a finite result — the saturating_sub safety net documented contract. Finite-output invariant across every legal padded index. The zero-copy padder is performance-critical for long-form audio; pinning its symbolic mirror math prevents a future "optimisation" from silently producing wrong padded values. Workspace clippy clean. |
| **v0.9.42** | 2026-06-30 | **Pre-v1.0 waveform_to_carrier STFT pipeline invariant coverage pass.** Adds 6 new unit tests for `provcheck-watermark::stft::waveform_to_carrier` — the top-level forward-STFT path the silentcipher encoder + decoder hot paths both invoke. Empty input → StftError::Empty (catches a future maintainer removing the early guard). Carrier layout invariant: output length is exactly FREQ_BINS × n_frames (the `[bin][t]` flat-index contract the encoder ONNX expects). Carrier values are all finite (no NaN/inf from the `sqrt(re² + im²)` magnitude computation). Carrier values are all non-negative (catches a future sign-flip in the magnitude path). For non-trivial input there exists at least one nonzero magnitude (catches a future bug that would zero the carrier). Frame-count monotonicity: a longer input produces strictly more frames than a shorter one (pins the always-pad-then-frame invariant across input lengths). The forward STFT is the load-bearing wire-format step between operator audio and the ONNX models; pinning these invariants prevents any silent corruption of the encoder/decoder I/O. Workspace clippy clean. |
| **v0.9.41** | 2026-06-30 | **Pre-v1.0 SigningKeyRecord serde wire-format coverage pass.** Adds 11 new unit tests for `provcheck-attestation-spec::SigningKeyRecord` — the at-proto record format that creators publish under `app.provcheck.signingKey` and verifiers fetch + parse. **Lexicon camelCase rename pins × 4**: `createdAt` (not `created_at`), `validFrom` (not `valid_from`), `validUntil`, `supersededBy`. Each rename verified explicitly so a silent removal of a `#[serde(rename)]` attr would fail at test time rather than at deployment time when verifiers reject the wrong-cased records. `skip_serializing_if` pins × 4: None label/validFrom/validUntil/supersededBy all omitted from JSON. Required fields always emitted (createdAt + fingerprint + algorithm). Full round-trip with every optional populated. **Backward-compat deserialise of legacy record with only required fields** (all optionals default to None). The on-wire camelCase is the at-proto cross-process contract; any drift breaks every published signing-key record. Workspace clippy clean. |
| **v0.9.40** | 2026-06-30 | **Pre-v1.0 ALLOWED_ALGORITHMS + IdentityClaim wire-contract coverage pass.** Adds 12 new unit tests for `provcheck-attestation-spec` (lexicon-level wire contracts that every signer + verifier reads). ALLOWED_ALGORITHMS × 3: all 10 documented JWS algs present (ES256/ES384/ES512/PS256/PS384/PS512/RS256/RS384/RS512/Ed25519), exact length pin = 10 (catches a silent expansion that lets verifiers accept records under a weaker algorithm), HMAC family + "none" rejected (C2PA chain is public-key only). IDENTITY_ASSERTION_LABEL × 2: pinned to `"app.provcheck.identity"`, reverse-DNS form invariant. IDENTITY_CLAIM_SCHEMA_VERSION = 1 pinned. IdentityClaim × 6: `new` sets current schema version, preserves DID + handle, None handle stays None, `serde` omits None handle, `serde` omits None version, **backward-compat deserialise of legacy record without version field** (defaults to None, doesn't fail — pins that old shipped builds still parse), full round-trip. The constants + serde are the cross-process wire contract every signer / verifier reads; silent drift here corrupts every signed asset across the ecosystem. Workspace clippy clean. |
| **v0.9.39** | 2026-06-30 | **Pre-v1.0 looks_like_image gate + cross-module allowlist parity coverage pass.** Adds 6 new unit tests for `provcheck-image::looks_like_image`. All 8 documented image extensions (png/jpg/jpeg/webp/bmp/gif/tiff/tif) accepted. Audio extensions (mp3/wav/flac/aac/ogg/m4a) rejected (catches an accidental allowlist merge with the audio crate). Text extensions (txt/md/json/html) rejected. Case-insensitive lookup (Windows uppercases). No-extension paths rejected. **Cross-module parity invariant**: every extension `looks_like_image` accepts must ALSO pass the early-exit gate in `image::decode` — pinned by writing a tempfile with junk body for each accepted extension and asserting `decode` returns anything other than NotImage. An asymmetry would mean the detector accepts a file that the decoder then rejects, silently rendering it NotDetected when the real verdict should be a decoder error. Workspace clippy clean. |
| **v0.9.38** | 2026-06-30 | **Pre-v1.0 WavMark classify + looks_like_audio + not_detected helper coverage pass.** Adds 10 new unit tests for `provcheck-wavmark::lib` (mirrors v0.9.37's AudioSeal pass for cross-detector parity). `classify` × 4: at DETECTED inclusive lower bound is Detected, at DEGRADED inclusive lower bound is Degraded, below DEGRADED → NotDetected, just below DETECTED → Degraded. `looks_like_audio` × 5: all 14 documented audio extensions accepted, image/text rejected, case-insensitive (Windows uppercases), no-extension rejected, cross-crate parity invariant documented (wavmark and audioseal allowlists must remain identical so the audio-modality routing layer can use either as the gate without surprising drift). `not_detected` helper × 1: sets WavMark kind, NotDetected, zero confidence, all-None payload/brand/marked_regions, message preserved. With v0.9.37 (audioseal) + v0.9.38 (wavmark) both detector families now have parallel coverage of the same surface. Workspace clippy clean. |
| **v0.9.37** | 2026-06-30 | **Pre-v1.0 AudioSeal classify + looks_like_audio + not_detected helper coverage pass.** Adds 9 new unit tests for `provcheck-audioseal::lib` (was 3, now 12 lib + 17 detect + 16 brand registry = 45 total in crate). `classify` × 4: at DETECTED_THRESHOLD inclusive lower bound is Detected, at DEGRADED_THRESHOLD inclusive lower bound is Degraded, below DEGRADED → NotDetected, just below DETECTED → Degraded (strict-inequality pin). `looks_like_audio` × 4: all 14 documented audio extensions (mp3/mp4/wav/flac/aac/m4a/m4b/mov/ogg/oga/opus/wma/aiff/aif) accepted, image/text extensions rejected, case-insensitive (Windows uppercases), no-extension paths rejected. `not_detected` helper × 1: sets WatermarkKind::AudioSeal, NotDetected status, zero confidence, no payload/brand/marked_regions, message preserved. The extension matcher saves loading the 33 MB ONNX runtime when someone hands a PNG to the audio detector; pinning catches a future maintainer who shortens the list without realising the cost. Workspace clippy clean. |
| **v0.9.36** | 2026-06-30 | **Pre-v1.0 image decode early-exit + constants coverage pass.** Adds 8 new unit tests for `provcheck-image::image::decode` (was 1, now 9). Early-exit branches × 5: unrecognised extension `.xyz` → NotImage, audio extension `.wav` → NotImage (pinned not in image allowlist even though some headers overlap), missing file → Io error, all 7 documented image extensions (jpg/jpeg/webp/bmp/gif/tif/tiff) pass the early gate (junk body → Decode, NOT NotImage), case-insensitive extension lookup (`.PNG` passes — Windows operators have UPPER extensions everywhere). Constants × 3: MODEL_RES = 256 (TrustMark input resolution; bumping requires re-training), MAX_IMAGE_DIM = 8192 (v0.9.0 audit §2.3 decompression-bomb guard — pinned so a future maintainer can't silently raise past the threat-model boundary), MAX_IMAGE_ALLOC = 256 MB. The early-exit gate is the first cliff every image verify call hits; the constants are the security threat-model contract from the v0.9.0 audit. Workspace clippy clean. |
| **v0.9.35** | 2026-06-30 | **Pre-v1.0 AudioSeal detect threshold + pack_bits + regions coverage pass.** Adds 9 new unit tests for `provcheck-audioseal::detect` (was 8, now 17). PRESENCE_THRESHOLD = 0.5 pinned. MIN_REGION_SAMPLES = 16_000 (1 sec @ 16 kHz) pinned. `pack_bits` exhaustive: for each of the 16 bit positions, setting only that bit must land at the documented byte (i/8) and bit (7 - i%8) — catches a future endianness or shift-direction drift. Strict-greater-than-half threshold: exactly 0.5 must NOT set the bit; 0.5001 must. `regions_above_threshold` edges × 4: empty presence → empty regions, all-below → empty regions, unterminated run reaching buffer end is still reported (a common-mode bug that an explicit "did we close the open span" loop end check protects against), multiple separated runs each reported. The pack_bits projection is the AudioSeal wire-format contract; regions_above_threshold drives the marked_regions UI surface — pinning these prevents silent regressions that would corrupt either the payload byte order or the localisation rendering. Workspace clippy clean. |
| **v0.9.34** | 2026-06-30 | **Pre-v1.0 brand-payload constants + parse_brand edge coverage pass.** Adds 10 new unit tests for `provcheck-watermark::brand` (was 6, now 16). PAYLOAD_RAIDIO / PAYLOAD_DOOMSCROLL / PAYLOAD_VAIDEO each pinned exactly to their `b"XXX" + schema=1 + reserved=0` bytes. All three constants round-trip through `parse_brand` to the matching `WatermarkBrand` variant (catches drift between the PAYLOAD_* table and the parser's BRAND_* table). All constants use schema byte = 1 (the only documented schema). All constants use reserved byte = 0. `SCHEMA_BYTE_INDEX` = 3 pinned (catches future schema-2 work that accidentally shifts the tagged-union key). `parse_brand` edges × 3: lowercase ASCII is NOT a known brand (case-sensitive registry), schema 0 → UnknownSchema (not silently treated as schema 1), schema 0xFF → UnknownSchema. The PAYLOAD_* constants are the public wire-format contract embedders write; pinning every byte catches a typo that would silently break every signed file. Workspace clippy clean. |
| **v0.9.33** | 2026-06-30 | **Pre-v1.0 audio resample-helper coverage pass.** Adds 5 new unit tests for `provcheck-watermark::audio::resample` — the SincFixedIn-backed sample-rate converter on the verifier's hot path. Identity case (src == dst rate) produces near-input-length output. Upsample 22050 → 44100 ≈ 2x output length. Downsample 88200 → 44100 ≈ 0.5x output length. Finite-input invariant: NO NaN or infinity samples (catches a future SincFixedIn config that silently divides by zero on edge cases). Short input below chunk_size (4096) still produces output via tail-pad path. The resampler is the load-bearing helper for every non-44.1 kHz input the verifier sees; pinning these invariants prevents a silent regression that would corrupt detection on the long tail of off-spec audio. Workspace clippy clean. |
| **v0.9.32** | 2026-06-30 | **Pre-v1.0 SynthID-text helpers + math invariant coverage pass.** Adds 14 new unit tests for `provcheck-synthid-text` (was 5, now 19). `tokenize` × 5: lowercases, strips punctuation but keeps hyphens and underscores (identifiers + hyphenated words survive), drops empty tokens (pure-punctuation chunks), empty/whitespace input → empty vec, preserves alphanumerics including digits. **`erf` math invariants × 4**: erf(0) = 0, odd-function symmetry erf(-x) = -erf(x), bounded in [-1, 1], erf(1) ≈ 0.8427 (textbook A&S precision pin). **`standard_normal_cdf` × 3**: Φ(0) = 0.5 by symmetry, monotonic increasing across [-3, 3], bounded in [0, 1]. **`classify` × 2**: SynthID-text never carries a brand payload (the mark is in token choices, not bytes — pinned across all confidence values), uses canonical `provcheck::confidence` DETECTED/DEGRADED thresholds (catches per-detector threshold override drift). The erf approximation is the Bayesian z-score's load-bearing math; pinning textbook values catches a future maintainer who "fixes" the A&S 7.1.26 constants. Workspace clippy clean. |
| **v0.9.31** | 2026-06-30 | **Pre-v1.0 records NSID + AtUri edge + RecordsError Display coverage pass.** Adds 10 new unit tests for `provcheck-publish::records` (was 14, now 24). COLLECTION_NSID pinned to `"app.provcheck.signingKey"` (matches the lexicon — silent change invalidates every existing published record). NSID reverse-DNS form invariant: exactly 2 dots, `app.provcheck.` prefix. AtUri edge cases × 3: empty string returns None rkey, no-slash input returns the whole string as rkey (pinned behaviour, since rsplit on no-slash yields the original), equality compares inner strings. RecordsError Display × 5: `PdsRejected` includes inner message, `NoSession` directs the operator to "kit login" (the CLI exit-code-3 path's only debugging clue), `Shape` includes inner message, `Http` includes inner message, `InvalidIdentifier` includes the offending input string. The COLLECTION_NSID is the at-proto wire contract that downstream verifiers use to query a creator's published signing keys; pinning it explicitly catches any silent rename. Workspace clippy clean. |
| **v0.9.30** | 2026-06-30 | **Pre-v1.0 video extension matching + threshold-pin coverage pass.** Adds 9 new unit tests for `provcheck-video` (was 11, now 20). `looks_like_video` × 5: accepts all 6 documented extensions (mp4/mov/mkv/webm/avi/m4v), case-insensitive (Windows uppercases), rejects audio/image/text extensions, rejects no-extension paths, rejects empty-extension paths. `not_video` early-return × 1: returns TrustMarkVideo kind, conf 0.0, message "not video". `missing_ffmpeg` × 1: install hint contains "ffmpeg" + at least one of (apt / brew / winget) so the operator can copy-paste the right command for their platform. Threshold pins × 2: MIN_DETECTED_FRAMES = 3 (bumping silently shifts every video verdict), tier ordering invariant MIN_DEGRADED_FRAMES < MIN_DETECTED_FRAMES. The extension matcher is the first cliff every verifier call hits; the install-hint string is the operator's only debugging clue when ffmpeg isn't on PATH. Workspace clippy clean. |
| **v0.9.29** | 2026-06-30 | **Pre-v1.0 SubjectInfo default coverage pass.** Adds 6 new unit tests for `provcheck-sign::cert::SubjectInfo` defaults — the operator-facing strings that appear in every locally-minted cert chain. CN = "Local Content Signer" pinned. Organisation references "provcheck-kit" pinned. Organisation marks "user-generated" (signals to anyone reading the chain that this is not vendor-issued — pinned explicitly). CA CN = "Local Install CA" pinned. All three default strings non-empty (catches a future maintainer who blanks one in a refactor). Custom-override round-trip works. These strings show up in c2pa-rs's reader output, third-party C2PA verifiers, and operator screenshots — a silent default-string change would visibly drift across the ecosystem. Workspace clippy clean, cert now at 13 tests. |
| **v0.9.28** | 2026-06-30 | **Pre-v1.0 persist on-disk layout + PersistError Display coverage pass.** Adds 8 new unit tests for `provcheck-sign::persist` path helpers + error variants. Path helpers × 5: `keys_dir(base)` = `base/keys`, `chain_pem_path` = `base/keys/signing.pem`, `identity_json_path` = `base/keys/identity.json`, `age_key_path` = `base/keys/signing.key.age` (operators back this up to a fresh machine via the documented filename — external `rage` CLI reads it). Cross-helper consistency: every per-file path lives under `keys_dir(base)`. PersistError Display × 3: DataDirUnavailable, UnsupportedSchemaVersion (both numbers in the message), EmptyChain includes path. The on-disk layout is the operator's backup contract; pinning these invariants means no future refactor can silently break the path-based backups operators depend on. Workspace clippy clean, persist now at 17 tests. |
| **v0.9.27** | 2026-06-30 | **Pre-v1.0 publish session helper coverage pass.** Adds 9 new unit tests for the sync helpers in `provcheck-publish::session`. `normalise_pds_url` × 5: leading whitespace trimmed, trailing whitespace trimmed, trailing slash dropped, path components preserved (self-hosted PDS at subpath), localhost+port preserved. `write_session_file` × 4: creates `session.json` in target dir, pretty-prints (operators hand-edit), creates missing parent directories (fresh data-dir bootstrap), JWTs round-trip preserved verbatim (the at-rest format the resume-session path depends on). The pure-sync surface around session persistence is the entry-pipe between the kit CLI and atrium; pinning these helpers means a future maintainer can't silently break operator-friendly URL normalisation or the at-rest session schema. Workspace clippy clean. |
| **v0.9.26** | 2026-06-30 | **Pre-v1.0 AttestationConfig + options-mapping coverage pass.** Adds 9 new unit tests for `provcheck-platform::attestation` — the module previously had zero direct test coverage despite carrying the kit's identity-options-to-transport-config mapping. `AttestationConfig::default()` has all overrides absent. `AttestationOptions::default()` has all flags off. `From<&AttestationOptions> for AttestationConfig` × 4: preserves cache_dir (Option<PathBuf>), maps `no_cache` → `bypass_cache`, no_cache=false leaves bypass_cache=false, test-only override fields (bsky_api_override / plc_directory_override / use_http_for_well_known) never leak through from production CLI options. `attestation_failure_reason` × 3: Mismatch names "signing certificate not attested", NotPublished names "no signing-key records", ResolutionFailed names "DID resolution failed". Pins the conversion + failure-message contracts so a future maintainer can't accidentally drop a relevant option or leak a test override into production config. Workspace clippy clean. |
| **v0.9.25** | 2026-06-29 | **Pre-v1.0 WatermarkResult wire-format coverage pass.** Adds 11 new unit tests for `provcheck::report::WatermarkResult` serde. Required fields (`kind`, `status`, `detected`, `confidence`) always serialise. Optional fields (`payload`, `brand`, `message`, `marked_regions`) omitted via `skip_serializing_if = "Option::is_none"` when None. `WatermarkStatus` snake_case wire format pinned (`degraded` not `Degraded`, `not_detected` not `notDetected`). `WatermarkKind` snake_case pinned (`trust_mark_video` for multi-word). `WatermarkBrand` uses `#[serde(tag = "code")]` so brand serialises as `{"code": "raidio"}` not bare string — pinned to catch any drift. Full round-trip through `serde_json` for a populated result with payload + brand + message + marked_regions. **Backward-compat**: legacy verifier outputs without the `marked_regions` field still deserialise (defaults to None) — pin so a future maintainer can't accidentally break parsing of pre-v0.7 reports. Workspace clippy clean. |
| **v0.9.24** | 2026-06-29 | **Pre-v1.0 Report serialization + Display coverage pass.** Adds 13 new unit tests for `provcheck::report::Report` — the public wire contract for GUI / CI / JSON-mode automation that previously had zero direct coverage. `exit_code` × 2: 0 when verified, 1 otherwise. `to_json_string` × 5: pretty-printed (newlines + indentation), includes `verified` field, omits empty `watermarks` vec (`skip_serializing_if = "Vec::is_empty"`), omits empty `parents` vec, round-trips through `serde_json::from_str`. `Display` × 4: `[UNSIGNED]` marker for unsigned reports, `[VERIFIED]` for verified, `[INVALID]` for not-verified-and-not-unsigned, `failure_reason` rendered when present. Plus 2 `format_regions` extras: en-dash (U+2013) used not hyphen (catches normalisation that would invalidate downstream parsers), empty list produces empty string. The Report is the user-facing automation contract — silent regressions corrupt every CI gate the operator wires it into. Workspace clippy clean. |
| **v0.9.23** | 2026-06-29 | **Pre-v1.0 confidence-threshold + classify coverage pass.** Adds 13 new unit tests for `provcheck::confidence` — the canonical confidence-threshold module every detector family re-exports. This module previously had ZERO tests despite being the load-bearing classifier for every verifier verdict. DETECTED_THRESHOLD = 0.70 pinned. DEGRADED_THRESHOLD = 0.50 pinned. DETECTED > DEGRADED ordering invariant. Both thresholds ∈ [0, 1]. Eight `classify(valid, confidence)` boundary tests: invalid=false always returns NotDetected regardless of confidence (the false-positive defence), confidence < DEGRADED → NotDetected, confidence at DEGRADED exactly → Degraded (inclusive lower bound pin), confidence ∈ [0.50, 0.70) → Degraded, confidence at DETECTED exactly → Detected, confidence ≥ DETECTED → Detected. NaN-safety: classify with NaN confidence is deterministic and doesn't panic. Just-below-threshold strict-inequality pins (0.69 → Degraded, 0.49 → NotDetected). The threshold semantics live across every detector family — a silent bump invalidates every signed asset's report. Workspace clippy clean. |
| **v0.9.22** | 2026-06-29 | **Pre-v1.0 BCH boundary + invariant coverage pass.** Adds 6 new unit tests to `provcheck-image::bch` (now at 18 tests total covering the full BCH(127, 92, t=5) wire-format contract). Encode determinism: same input twice must produce identical codewords (catches accidental non-determinism a future optimisation might introduce). Encoded codeword length always = N (= 127). Systematic invariant: input data bits land at codeword positions [PARITY_BITS..N] bit-identical (the "data passes through unchanged in the high half" contract that classify_bch5 depends on). Decode of zero-data codeword recovers zero data. Errors at codeword boundaries (position 0 and N-1) are corrected. Burst errors: 4 consecutive bit flips within t=5 are corrected. These pin every documented BCH wire-format contract so a future maintainer cannot silently break the image-modality encoder ↔ decoder symmetry. Workspace clippy clean. |
| **v0.9.21** | 2026-06-29 | **Pre-v1.0 VCTK rescale + reflect-pad invariant coverage.** Adds 6 new unit tests pinning the STFT pre-processing helpers in `provcheck-watermark::stft`. `vctk_rescale` × 3: length-preservation across sizes 1/17/100/1000/50000, uniform-input produces finite output (no NaN), sign-preservation (positive samples stay positive, negative stay negative, zero stays zero — the carrier phase invariant). `reflect_pad` × 3: zero-pad returns original unchanged, output length is exactly `input_len + 2 * pad` across multiple pad sizes, inner samples at positions [pad..pad+len] are bit-identical to input (no transformation of the middle region). These pin the silentcipher Python parity contract — any drift from the documented `mean(y²) == VCTK_AVG_ENERGY` rescale or numpy `pad_mode='reflect'` semantics would silently invalidate every detection result. Workspace clippy clean, 560+ tests passing. |
| **v0.9.20** | 2026-06-29 | **Pre-v1.0 silentcipher decode-logits coverage pass.** Adds 7 new unit tests pinning `provcheck-watermark::decode::decode_logits` — the function that takes raw silentcipher decoder logits and recovers the 5-byte payload + confidence + tile-quality vector. Round-trip for VAI (third registered brand), all-zero payload, all-0xFF payload (edge corners of the 40-bit space). Clean-input confidence pin: synthetic logits matching a tile-aligned message produce confidence == 1.0 exactly. `tile_quality` length-equals-n_tiles invariant on valid input, empty `tile_quality` on invalid input (no stale buffer). Per-tile quality values are all in [0, 1]. The decode pipeline is the verifier's hot path; pinning these invariants prevents silent regressions that would corrupt either the recovered payload or the localisation that drives `marked_regions`. Total 548 tests passing. |
| **v0.9.19** | 2026-06-29 | **Pre-v1.0 `embed_identity_assertion` C2PA-splicing coverage pass.** Adds 11 new unit tests covering `provcheck-sign::sign::embed_identity_assertion` — the function that splices the `app.provcheck.identity` C2PA assertion into the producer's manifest JSON. Empty-object manifest gains assertions array + identity assertion. DID + handle preservation in the assertion's `data` field. Handle correctly omitted (not nulled) when None via `serde(skip_serializing_if)`. **Idempotency under re-embed** — re-running embed_identity_assertion replaces the existing identity assertion rather than appending a duplicate. **Preservation of unrelated assertions** — pre-existing `c2pa.actions.v2` or other assertions stay intact when identity is added or replaced. Error paths: malformed JSON → `ManifestJson`, non-object top-level → `ManifestJson("not an object")`, non-array `assertions` field → `ManifestJson("not an array")`. Output round-trips as valid JSON. This is the load-bearing identity-claim splicing logic for every signed asset; pinning idempotency + preservation invariants prevents silent regressions that would corrupt creator manifests. Total 541 tests passing. |
| **v0.9.18** | 2026-06-29 | **Pre-v1.0 wavmark brand-registry coverage + cross-crate parity.** Adds 8 new tests pinning `provcheck-wavmark::registry`'s encode + decode invariants beyond the existing 3-test smoke. Encode pins for BRAND_RAIDIO (0x0842) and BRAND_VAIDEO (0x0C63), generalised single-bit-flip tolerance across all three brands (not just doomscroll), reserved bit always 0 invariant, ID_MASK = 0x1F with exactly 5 bits set, decode(0) → 0 (no-signal contract), pessimal two-bit-flip in one copy still recovers (majority-vote stress test). **Cross-crate parity test**: `encoding_matches_audioseal_registry_for_same_brand` asserts that wavmark and audioseal produce bit-identical encodings for the same brand id, across all 32 possible ids. Without this invariant, an audioseal-marked stream couldn't be re-tagged via wavmark and vice versa — a silent drift between the two crates would corrupt every dual-detector workflow. Total 530 tests passing. |
| **v0.9.17** | 2026-06-29 | **Pre-v1.0 letters_encoding wire-format pass.** Adds 7 new unit tests pinning `provcheck-watermark::encode::letters_encoding` — the function that produces the silentcipher encoder ONNX's message tensor from a 5-byte payload. Output-size invariant (MESSAGE_DIM × T = 5 × T f32s across t_frames = 1, 21, 50, 100, 1000), one-hot per time-slot invariant (exactly one 1.0 per t with all other dims 0.0), terminator-at-position-20-is-dim-0, zero-payload produces all-dim-1 across the payload positions, max-payload (0xFF) produces all-dim-4, MSB-first 2-bit chunking pinned via the `0x44 = 0b01000100 → 01,00,01,00 → +1 = 2,1,2,1` mapping, short t_frames truncation. The wire format is the kit's contract with the ONNX encoder; a layout drift would silently corrupt every embed. Total 522 tests passing. |
| **v0.9.16** | 2026-06-29 | **Pre-v1.0 sign-action + MIME-format coverage pass.** Adds 20 new unit tests pinning `default_action_for` (the C2PA action chooser) and `format_for_ingredient` (the extension → MIME-type mapper). `default_action_for` × 3: no provenance → Created (the unsigned-source default), existing provenance → Published (the publisher-attestation case), minimal-fields provenance still → Published. `format_for_ingredient` × 17: all 13 mapped extensions (wav/mp3/flac/ogg/oga/m4a/aac/jpg/jpeg/png/tif/tiff/webp/mp4/m4v/mov/webm), unknown extension falls back to application/octet-stream, no-extension fallback, case-insensitive extension lookup (Windows uppercases), full-path Unix + Windows handling. The MIME-mapping is the kit's contract with C2PA's Ingredient hashing; a typo in the table would silently misclassify the asset. Total 515 tests passing. |
| **v0.9.15** | 2026-06-29 | **Pre-v1.0 sign-algorithm parser coverage pass.** Adds 12 new unit tests covering `provcheck-sign::sign::parse_algorithm` (the JOSE algorithm-name to `c2pa::SigningAlg` mapper). All 7 supported names round-trip (ES256/ES384/ES512/PS256/PS384/PS512/Ed25519). Rejects lowercase variants (lexicon is case-sensitive). Rejects RS256 explicitly — it's in `ALLOWED_ALGORITHMS` per the lexicon but c2pa doesn't expose it; pinning the rejection surfaces the gap as a typed failure. Rejects empty string + arbitrary unknown algs. Cross-checks every parsable name against `provcheck_attestation_spec::ALLOWED_ALGORITHMS` so silent drift between the kit's signing surface and the lexicon's accept-list fails at test time rather than at deployment. Total 495 tests passing. |
| **v0.9.14** | 2026-06-29 | **Pre-v1.0 model-architecture invariants + hex_lower wire-format coverage pass.** Adds 17 new tests pinning the silentcipher hparams constants and the attestation-spec hex_lower helper. `hparams` × 10: SAMPLE_RATE = 44.1 kHz (matches model training distribution), FREQ_BINS = N_FFT/2+1 (real-FFT identity), HOP = N_FFT/2 (50% overlap by design), WIN = N_FFT, MESSAGE_LEN = 21 (20 payload + 1 terminator), MESSAGE_DIM = 5 (terminator + 4 payload channels), VCTK_AVG_ENERGY positive-finite-and-order-of-magnitude check (catches typos that drift 10× either way), confidence thresholds re-export canonical provcheck::confidence values, detected > degraded, both ∈ [0,1]. `hex_lower` × 7: empty → empty, single-byte 0x00 → "00", 0xFF → "ff" (strict lowercase per lexicon), 2-char-per-byte invariant, length-doubling invariant, all 256 byte values produce only `[0-9a-f]` chars, sha256("") known-value pin. The model-architecture invariants catch silent hparams drift that would invalidate every existing detection result; the hex_lower invariants catch any drift from the lexicon's `[0-9a-f]{64}` fingerprint pattern. Total 483 tests passing. |
| **v0.9.13** | 2026-06-29 | **Pre-v1.0 STFT public-helper coverage pass.** Adds 8 new unit tests pinning the public STFT-pipeline helpers in `provcheck-watermark::stft`: `compute_n_frames` (frame-budget formula gating every streaming embed call) and `streaming_utterance_norm` (silence-detection input to the silentcipher rescale step). `compute_n_frames` × 5: zero for too-short input, one at exact N_FFT, one until first hop boundary, two at N_FFT + HOP, linear growth on a 1-second waveform at 44.1 kHz. `streaming_utterance_norm` × 3: rejects empty waveform, pads-and-runs on short waveform (returns Ok, not TooShort — pins the documented contract), returns finite non-negative value on long silent buffer. Total 476 tests passing. |
| **v0.9.12** | 2026-06-29 | **Pre-v1.0 image-encode internal-helper coverage pass.** Adds 13 new unit tests pinning the pure-math helpers in `provcheck-image::encode`: `denorm` (the [-1,1] → [0,255] map), `chw_normalised_to_rgb_u8` (CHW-to-HWC pixel-layout converter), and `resize_residual_chw` (bilinear resize). Covers boundary inputs (-1 / 0 / +1), over/under-clamp behaviour (NaN → 0, ±100 → 0/255 not wraparound), per-channel layout invariants (R=-1/G=0/B=+1 → 0/128/255), and bilinear resize identity / upsize / downsize / uniform-input invariants. The internals support the BCH-5 encoder's residual blending; pinning them prevents a future maintainer from silently breaking the encoder's wire-format symmetry with the decoder. Total 468 tests passing. |
| **v0.9.11** | 2026-06-29 | **Pre-v1.0 secret-redaction + image-error coverage pass.** Adds 11 new unit tests covering the secret-redaction contract on `provcheck-publish::SessionFile` serde (must NOT redact — at-rest persistence depends on round-tripping the JWT) and full `provcheck-image::EncodeError` + `ImageError` Display + `From` coverage. Pins the distinction between the AtprotoClient Debug redaction (protect log output) vs SessionFile serde (persist for next-run reload). EncodeError × 6: Read / Write / Model / Io message inner preservation, Io `From<std::io::Error>`, Model `From<ModelError>`. ImageError × 4: NotImage message, Decode inner preservation, Io inner, Io `From`. Total 455 tests passing. |
| **v0.9.10** | 2026-06-29 | **Pre-v1.0 audio + STFT error-surface coverage pass.** Adds 10 new unit tests for `provcheck-watermark::audio::AudioError` and `provcheck-watermark::stft::StftError`. AudioError × 8: NotAudio message includes "audio container", Decode / Resample / Io message inner preservation, `Io From<std::io::Error>` impl, `decode_to_mono_44k1` + `decode_to_stereo_44k1` on missing file → Io error, StereoDecoded struct field layout pin (catches accidental rename/reorder). StftError × 2: Empty + TooShort messages locked. Total 444 tests passing. |
| **v0.9.9** | 2026-06-29 | **Pre-v1.0 url_encode + resolve_handle input coverage pass.** Adds 12 new unit tests for `provcheck-platform::network`'s URL helpers and resolve_handle input validation. `url_encode` × 10: alphanumeric passthrough, RFC 3986 unreserved-set passthrough (`-_.~`), space → %20, colon → %3A (DID handling), slash → %2F, @-sign → %40, percent-sign → %25 (double-encoding hazard pinned), UTF-8 multi-byte → per-byte percent, empty → empty, upper-case hex digits per RFC 3986. `resolve_handle` × 2: empty handle errors, whitespace-only handle errors (network-touching success paths still need an httpmock harness — queued for v0.9.x with the atproto CRUD work). Total 434 tests passing. |
| **v0.9.8** | 2026-06-29 | **Pre-v1.0 `classify_bch5` thorough coverage pass.** Adds 11 new unit tests pinning the image-modality detector's BCH-5 classification surface. Covers: short-input bail (< 100 bits → NotDetected), wrong version-bits (≠ 0b0001 → NotDetected), all-zero version-bits → NotDetected, clean payloads for all three known brands (doomscroll / rAIdio / vAIdeo) decode to Detected with the correct brand, unknown brand id (4) → Detected with brand=None, BCH error correction at t=1 / t=5 (must succeed), BCH at t=6 (exceeds capacity → NotDetected), and corrupted magic byte → NotDetected. Tests construct the BCH codeword via `encode::test_build_secret_for_bch5` so the encoder + classifier are tested round-trip without an ONNX model. The image detector's verdict logic was previously only exercised via the model integration smoke; v0.9.8 covers every documented branch directly. Total 422 tests passing. |
| **v0.9.7** | 2026-06-29 | **Pre-v1.0 documentation-rot sweep.** Fixes SECURITY.md "Supported versions" section that still said `v0.4.x` (stale by 5 minor releases). Now points at `vX.Y.0` as the supported tag family and explicitly notes that iteration tags (`vX.Y.Z` with Z > 0) are commit anchors only, not for installation. Rewrites README's top-level Status sentence that still claimed `v0.6.0 shipped` as the headline (v0.6 closed audio throughput / memory / GPU; v0.7 added multimodal; v0.9 wired video + text + ComfyUI). The v0.9.x line is documented as the pre-v1.0 test-coverage push. No code changes; doc-only. Total 411 tests still passing. |
| **v0.9.6** | 2026-06-29 | **Pre-v1.0 payload parser + manifest stability pass.** Adds 16 new unit tests pinning the kit's `parse_payload_hex` parser and the DLC manifest's wire-format invariants. `parse_payload_hex` × 8: doomscroll/rAIdio round trips, whitespace-tolerance (operator-pasted strings), wrong-length input surfaces a clear count, empty input errors, non-hex character names the byte position in the error chain, uppercase + mixed-case hex accepted (case-insensitive). Manifest × 8: non-empty list, URL-tail = filename invariant (cache hits depend on this), every URL points at `github.com/CreativeMayhemLtd/provcheck/releases/download/`, no all-zero placeholder SHA256s, no zero-size entries, (family, variant) tuples unique (catches accidental duplicate entries that would silently load wrong bytes), filenames unique, trustmark family has both decoder + encoder variants (image-modality half-works without one). Also lands `.github/workflows/release.yml` gate change so iteration tags (this one included) skip the matrix and only `vX.Y.0` major / minor tags fire it. Total 411 tests passing. |
| **v0.9.5** | 2026-06-29 | **Pre-v1.0 kit dispatch + brand-registry coverage pass.** Adds 16 new tests pinning kit dispatch helpers (`stamp::detect_modality`, `stamp::brand_id_to_payload_hex`) and the watermark `resolve_output_channels` matrix. `detect_modality` × 6: classifies all 9 audio extensions (mp3/wav/flac/m4a/ogg/opus/aac/mp4/mov), all 8 image extensions (png/jpg/jpeg/webp/bmp/gif/tiff/tif), case-insensitivity (Photo.JPG / MUSIC.MP3), missing-extension diagnostic, unsupported-extension diagnostic, full-path handling (Unix + Windows). `brand_id_to_payload_hex` × 6: doomscroll → `44464d0100`, rAIdio → `5241490100`, vAIdeo → `5641490100`, unknown brand fallback to doomscroll pinned across 0/4/5/16/31, always-10-chars wire-format invariant, lowercase-hex invariant. `resolve_output_channels` × 4: Mono mode forces 1ch regardless of source, Stereo mode forces 2ch regardless of source, Auto mode matches source for 1+2ch, Auto downmixes 3/6/8 channel sources to stereo. The kit stamp + watermark dispatch carries the brand-registry wire format; pinning these prevents a future maintainer from silently re-tagging unregistered creators under the wrong brand. Total 395 tests passing. |
| **v0.9.4** | 2026-06-29 | **Pre-v1.0 CLI binary integration coverage pass.** First-ever tests for the `provcheck` binary: 9 end-to-end integration tests in `crates/provcheck-cli/tests/exit_codes.rs` exercise the documented exit-code contract by spawning the cargo-built binary via `CARGO_BIN_EXE_provcheck`. Each documented exit-code path is now pinned: 0 on `--help` / `--version`, 1 on require-* gate demotion (deferred to v0.9.x since exercising it needs a signed asset fixture), 2 on missing positional / malformed trust-store PEM / unreadable trust-store path / missing input file / `--require-attested` without an identity input / `--require-watermark` conflicting with `--no-watermark` / `--json` mode preserving the same exit codes. Total 379 tests passing. The CLI binary was the user-facing contract carrying zero tests for the entire v0.x series; v0.9.4 closes that gap. |
| **v0.9.3** | 2026-06-29 | **Pre-v1.0 cache + spec-stability coverage pass.** Adds 18 new unit tests covering platform cache behaviour and attestation-spec stability invariants. `provcheck-platform::storage` gains 8 tests for the `CacheEnvelope` round-trip path: missing-file → cache miss, write-then-read round trip, garbled-json → cache miss (not panic), past-TTL envelope → cache miss, within-TTL envelope → cache hit, cache_path includes namespace directory, cache_write creates the namespace subdirectory, CACHE_TTL pinned at 24h. `provcheck-attestation-spec` gains 10 tests pinning the load-bearing wire-format constants: `ALLOWED_ALGORITHMS` full membership (catches accidental admit/demote), `IDENTITY_CLAIM_SCHEMA_VERSION` pinned at 1, `IdentityClaim::new` schema-version contract (regardless of handle), `FingerprintError` Display × 2, `fingerprint_pem_chain` empty + garbled rejection, `fingerprint_leaf_der` canonical format (sha256: prefix, 71-char length, lowercase hex), determinism, and avalanche on one-bit input change. Total 370 tests passing across the workspace. |
| **v0.9.2** | 2026-06-29 | **Pre-v1.0 error-surface coverage pass.** Adds 24 new unit tests pinning every typed-error variant's Display message: `RecordsError` × 5 (PdsRejected, Http, Shape, InvalidIdentifier, NoSession routes user to `kit login`), `SessionError` × 6 (SessionExpired → `kit login`, LoginRejected, Http, Format, InvalidIdentifier, Io From<std::io::Error>), `KitError` × 3 (SessionExpired → exit-code-3 mapping, Io, NotImplemented), `SignError` × 5 (Source, UnknownAlgorithm with quoted value, SignerSetup, ManifestJson, C2pa), `provcheck::Error` × 5 (Io, InvalidTrustStore, DidResolution, PdsAccess, AttestationFailed). Total 352 tests passing across the workspace, 0 failing, 10 ignored (intentional gates for network / hardware / weights-required). These tests catch accidental message edits that would regress the user-facing CLI diagnostic UX. |
| **v0.9.1** | 2026-06-29 | **Pre-v1.0 test-coverage + truth-in-docs pass.** Adds 28 new unit tests across the workspace (total 328 tests passing): SHA-mismatch arms on the DLC integrity gate (6 tests), video majority-vote thresholds factored into `classify_votes` with 8 table tests (deterministic tie-break via BTreeMap confirmed), `storage::sanitize_key` path-traversal defence (9 tests), `provcheck-image` `OutputShape`/`Load`/`Inference` error messages and the decompression-bomb cap relationships (4 tests), `embed_and_verify` early-return guard. Removes the dead `synthid::Error::Utf8` variant. Stale "scaffold" / "wiring pending" / "v0.9.x adds" docstrings rewritten across `WatermarkKind` variants, `provcheck-image` Cargo description + module doc + `detect` doc + `classify_bch5` comment, `provcheck-cli` dispatch comments, `provcheck-kit` `Kind::Image` doc + command-modules banner, ComfyUI README, README top-level Status section. Workspace passes `RUSTFLAGS=-D warnings cargo build`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. cargo audit posture unchanged. |
| **v0.9.0** | 2026-06-29 | **Video + text modalities wired; ComfyUI node live; CUDA EP diagnostic; pre-publish audit pass.** Closes the 7d / 7e wiring left as scaffolds in v0.7.0 and lands the ecosystem-reach piece from the v0.9 staging release. **Video (7d):** `provcheck-video` performs per-frame TrustMark-B inference via ffmpeg shell-out (one frame every 2 s, capped at 30, with a wall-clock cap), then temporal majority-vote on the recovered brand ids. Status=Detected when ≥3 frames recover the same brand id; Degraded when ≥2 frames recover any brand id; NotDetected otherwise. ffmpeg-on-PATH check fails gracefully with an install hint. Per-call temp dirs via `tempfile::TempDir` (O_EXCL + random suffix + Drop-on-panic cleanup). **SynthID-text (7e):** `provcheck-synthid-text` ships the real tournament-sampling Bayesian detection. For each token at position i, compute `g_i = hash(text[i-W..i], text[i], salt) ∈ [0, 1]`; aggregate `mean_g`; compute z-score against the unwatermarked baseline `0.5 ± sqrt(1/(12N))`; map to confidence via the standard normal CDF (Abramowitz-Stegun erf approximation). Pure-Rust SHA256-based hash, no FFI. File-size cap of 64 MB, content-sniff fallback for extensionless text, widened extension allowlist (`.html`, `.json`, `.csv`, etc.). Default word-level tokenizer ships now; HF subword tokenizer integration for Gemma / Llama / Qwen accuracy is a follow-up item. **ComfyUI node (9c):** `python/comfyui-node/` actually calls `provcheck-kit stamp` per generation. Saves tensor to temp PNG, shells out, reads stamped PNG back. Fails closed (passes input through with console warning) if `provcheck-kit` is missing from PATH so render queues don't crash. Brand-id clamped server-side as defence in depth. Brand-agnostic; any creator with their own atproto identity uses the same node. **CUDA EP diagnostic (issue #32):** `--features cuda` binary uses `.error_on_failure()` to detect when ort silently downgraded to CPU, emits a clear WARNING naming the prereqs, falls back explicitly to CPU. Default builds unaffected. **Image-decode hardening:** decompression-bomb caps (8192 × 8192 / 256 MB alloc) on every `image::ImageReader::decode` call; `u32` overflow at image-area math sites fixed by casting to `usize` first. **Audit pass:** 25+ items from a three-agent security + correctness + quality audit landed pre-publish (`#[allow(dead_code)]` brand constants, clippy lints across the workspace, doc-comment freshness, typed errors for stereo length mismatch, ffmpeg wall-clock cap, BTreeMap for deterministic video tiebreak). |
| **v0.7.0** | 2026-06-28 | **Multimodal expansion: image, video scaffold, text scaffold, creator UX moment, DLC weights.** Closes the audio-only-modality story v0.6 left in place. (7a, 7b, 7b-followup, 7c, 7c-followup) Image watermarking via Adobe / CAI's TrustMark-B (MIT code + MIT weights). End-to-end detect + embed through ort with full BCH(96, 61, t=5) ecosystem interop — a mark embedded by provcheck round-trips through Adobe's Python TrustMark and vice versa. Pure-Rust GF(2⁷) BCH implementation; no FFI. (7d, 7e scaffold) Video and SynthID-text modality crates scaffolded with verifier dispatch wiring; per-frame TrustMark + temporal vote and SynthID-text tournament-sampling detection wire in v0.7.x point releases. (7g) `kit stamp` — one-call creator pipeline that chains watermark + C2PA sign and auto-detects audio vs image. (8a) Every detector's trained weights move from `include_bytes!()` to download-on-demand DLC delivery via the new `provcheck-weights` crate. Kit binary drops from ~143 MB (v0.6.0 with everything bundled) to ~22 MB. `kit weights {status, install, uninstall}` per-family management — explicit consent, no `--all`, "always respect the user". Weights live on the public mirror's `weights-v1` release; SHA256-verified per download. (7b-followup) ort with `load-dynamic`; release archives now bundle the platform-specific onnxruntime CPU shared lib so downloaded binaries work without operator setup. (7-pre) Cross-crate primitives audit: wavmark gains stereo, audioseal + wavmark gain `EmbedConfig` wrappers, confidence thresholds promoted to `provcheck::confidence`, `embed_and_verify` primitive, Send+Sync assertion tests across the watermark crates. New roadmap doc set at `docs/v0.7.0-roadmap/`. |
| **v0.6.0** | 2026-06-28 | **Throughput + memory + GPU.** Four-phase release: (P1) chunk-parallel embed via rayon delivers 4× CPU speedup on default mode (29 min for a 56-min stereo episode vs v0.5.4's ~70 min). (P2) `kit serve` JSON-line stdin/stdout worker amortises model load across an entire batch (cold-start ~3s amortised over many files). (P3) Streaming embed via two-pass chunk-fused design (`--memory-budget streaming`) caps peak RSS at 5.0 GB on a 56-min stereo episode (vs 11.5 GB default-mode), trading ~1.6× real-time wall clock for 56% RSS reduction; also covers a `--memory-budget low` knob for chunk-sequential CPU. (P4) Optional CUDA backend via `--features cuda` routes the silentcipher embed encoder through `ort` 2.x's `CUDAExecutionProvider` for ~10× total speedup vs v0.5.4 (56-min stereo episode embeds in 6.6 min on an NVIDIA 3090). The default download stays a single tract-only CPU binary; the CUDA build is opt-in and requires operator-installed `onnxruntime-gpu` + CUDA 12.x + cuDNN. New roadmap doc set at `docs/v0.6.0-roadmap/` with the P1-P4 designs and the CUDA implementation notes. |
| **v0.5.4** | 2026-06-26 | **Clap surface cleanup + safe dependency bumps.** `--no-verify-after-embed` now actually parses (was broken in v0.5.3 by `ArgAction::Set` which only accepted `--verify-after-embed true|false`). serde_json 1.0.149 → 1.0.150, zeroize 1.8.2 → 1.9.0. No watermark code changes. |
| **v0.5.3** | 2026-06-24 | **AAC-in-MP4/M4A detector fix (public issue #24).** The detector silently returned conf 0.000 on AAC audio inside MP4 or M4A containers because symphonia 0.5.5's `isomp4` reader does not surface the `edts/elst` edit list or `iTunSMPB` tag as `codec_params.delay`, so we never trimmed the 1024-sample AAC encoder priming and every STFT frame was one AAC frame out of phase with the embedder's frame grid. Fix hardcodes `AAC_DEFAULT_PRIMING_SAMPLES = 1024` when symphonia returns `delay = None` for an AAC track (matches Lavf and most other AAC LC encoders), and adds `mp4`, `m4b`, and `mov` to the audio-extension allowlist so MP4 video containers with an AAC audio track make it past the early sniff. Silentcipher marks now survive AAC 192k stereo round-trips at conf 0.92, which corrects the v0.5.2 codec-survival doc's "AAC unsupported for silentcipher" claim — the embed always survived AAC; only the decoder was misaligned. AudioSeal stays the recommended path for AAC delivery (higher post-AAC margin), but silentcipher is now a viable second option. New `decode_probe` example under `crates/provcheck-watermark/examples/` for future container-alignment triage. |
| **v0.5.2** | 2026-06-24 | **Stereo embed + delivery-codec defaults + verify-after-embed.** New `--channels {auto, mono, stereo}` flag on `kit watermark`; `auto` matches input channels by running two independent mono embeds with the same payload, so stereo delivery pipelines no longer lose the mark to a downmix-then-upmix roundtrip. Silentcipher default SDR drops 47 → 30 dB so libmp3lame 192k delivery survives at conf 0.95+ (public issue #23); AAC delivery is documented as unsupported for silentcipher under any tested setting. AudioSeal default alpha rises 1.0 → 3.0 so the default behaviour reliably self-detects and survives AAC 192k at conf 0.999, plus libmp3lame 192k. New always-on `--verify-after-embed` self-test runs the matching detector against the freshly-written WAV; conf < 0.50 deletes the output file and exits non-zero so weak marks do not silently propagate downstream. Full parity report + codec compatibility matrix in [`docs/v0.5.2-codec-survival/`](docs/v0.5.2-codec-survival/). Pass `--sdr-db 47`, `--alpha 1.0`, or `--no-verify-after-embed` to restore v0.5.1 behaviour. |
| **v0.5.1** | 2026-06-22 | **Silentcipher embed OOM fix on multi-minute MP3s.** Production bug filed against doomscroll.fm's nightly pipeline (public issue #17): `provcheck-kit watermark` exited non-zero (SIGKILL from the Linux OOM killer) on inputs longer than about 40 minutes, around 100 million samples. The v0.3.8 embed-side chunking covered the ONNX inference call but did not chunk the message-tensor projection, which allocated a full `FREQ_BINS x n_frames` buffer up front (about 595 MB on a 56-minute episode). The fix moves the projection inside the chunk loop so only `FREQ_BINS x chunk_t` is materialised at any time, cutting the embed-side peak by roughly 1.2 GB. Round-trip parity is preserved; the chunked projection is bit-identical to the all-at-once reference. |
| **v0.5.0** | 2026-06-19 | **Yubikey HSM backend + Keys management tab.** New `kit init --yubikey` mints an ES256 keypair on PIV slot 9c — private key never extractable, every signature gates on the PIV PIN. `KeyProvider::signer()` trait method returning `Box<dyn c2pa::Signer>` is the integration seam; software backends inherit the default impl, Yubikey returns a custom signer that delegates to the device. GUI gains a new "Keys" tab between Verify and Sign showing local-vs-atproto state with mismatch detection and one-click revoke + rotate actions. Sign-tab loop bug fixed: superseded / revoked local fingerprints now route to a dedicated stale state with CLI recovery guidance instead of looping into "Publish key" + a conflict error. |
| **v0.4.2** | 2026-06-19 | **Marked-region localisation across all three detectors.** Silentcipher gains per-tile region derivation from its existing mode-vote match-fraction (no decoder change). CLI text mode prints span lists (`marked: 0:02–0:14, 0:21–0:58`); the GUI renders a horizontal timeline strip per detector with a shared horizontal scale so multi-detector hits line up visually. |
| **v0.4.1** | 2026-06-19 | **WavMark detect + embed** — third neural-watermark family. 32-bit payload (16-bit fix-pattern + 16-bit ECC-protected brand ID) at 16 kHz, STFT-based HiNet invertible-NN core, sliding-window decode at 50 ms resolution. New `kit watermark --kind wavmark`. STFT/iSTFT live in Rust because PyTorch's `return_complex=True` op rejects opset-17 ONNX export; only the HiNet block ships as ONNX. SDR ~54 dB on the embed roundtrip. |
| **v0.4.0** | 2026-06-19 | **AudioSeal detect + embed** — second neural-watermark family. 5-bit brand ID with 3-copy ECC (handles AudioSeal's ~6% per-bit error). 16 kHz time-domain pipeline. New `kit watermark --kind audioseal --brand-id 1` for embed. Adds `marked_regions` to verifier output for per-time-span localisation. New shared numeric brand registry. |
| v0.3.9 | 2026-06-18 | Detector early-exit + parallel chunks — **4.4× speedup** on a 60s marked file (98s → 22s). Workspace CI fix (rustdoc was choking on indented pseudocode in encode.rs). |
| v0.3.8 | 2026-06-18 | **Watermark EMBEDDING capability.** New `provcheck-kit watermark <input> -o <output.wav>` re-stamps silentcipher marks into audio that's had its original mark damaged by ffmpeg loudness normalisation. Embed wall-clock is ~0.8x real-time on a 60s file. |
| v0.3.7 | 2026-06-18 | Chunked watermark inference — fixes ~25 GB RSS blowup on multi-minute MP3s. Caps peak memory at ~1.5 GB regardless of audio length. Doomscroll-reported OOM closed. |
| v0.3.6 | 2026-06-16 | SBOMs land — every release now ships CycloneDX 1.6 + SPDX 2.3 for each binary. Release script hardened against transient GitHub API 502s. |
| v0.3.4 | 2026-06-16 | Docs sweep + GUI bundle naming fix. New `docs/creator-workflow.md`. |
| v0.3.3 | 2026-06-16 | silentcipher detector accuracy fix — honors MP3 LAME encoder delay + padding. Adds full Python reference + diagnostic harness (decode_dump / decode_diff / align_check). Structural Hann + always-pad alignments. |
| v0.3.2 | 2026-06-15 | Responsive verify UI (async + spawn_blocking). GUI watermark-detection toggle. Bundle naming fix so GUI installers sort above the GitHub-release-page fold. |
| v0.3.1 | 2026-06-14 | Publisher-attestation flow — `kit sign` on an already-signed file auto-chains as a derivative, preserving the original creator's provenance. |
| v0.3.0 | 2026-06-14 | Full creator side: `provcheck-kit` CLI + GUI Sign tab + `app.provcheck.identity` C2PA assertion + auto-bust attestation cache + standalone spec writeup. |
| v0.2.0 | 2026-06-10 | silentcipher detector live. Multi-detector slot scaffolded. GUI attestation parity. |
| v0.1.0 | 2026-06-04 | CLI + library on crates.io. Release binaries Win/Mac/Linux. Initial Tauri GUI build. |

Per-release commit and tag notes in [`release-notes/`](./release-notes/).

## Contributing

Issues and PRs welcome. The intended design is: `provcheck` (core
library) is the canonical verifier — CLI and GUI are thin adapters
over it. If behaviour differs between CLI and GUI, that's a bug in
the adapters, not the core. Same rule applies to the kit side:
`provcheck-sign` + `provcheck-publish` are libraries; `provcheck-kit`
is a thin CLI adapter over them. PRs that add new functionality
should land it in the library, not the adapter.

License-policy for new watermark detectors:
[`WATERMARK_LICENSE_POLICY.md`](./WATERMARK_LICENSE_POLICY.md).

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Authors

`provcheck` is maintained by **[Creative Mayhem UG](https://creativemayhem.com)**,
a Berlin studio. Website: [provcheck.ai](https://provcheck.ai).
Contact: [info@rAIdio.bot](mailto:info@rAIdio.bot).

The C2PA standard itself is developed by the
[Coalition for Content Provenance and Authenticity](https://c2pa.org).
The upstream [`c2pa` Rust crate](https://github.com/contentauth/c2pa-rs)
that does the heavy lifting is maintained by Adobe's Content
Authenticity Initiative.

We don't compete with any of that — we extend it.
