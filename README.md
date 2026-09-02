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

**v1.4.0 shipped 2026-08-31.** This is the current release. provcheck is a
feature-complete, Apache-2.0 provenance verifier and creator kit, with two
opt-in keyed forensic watermark add-ons under a separate source-available
license.

**The Apache-2.0 core (stable since v1.0.0, 2026-07-01):**

- **`provcheck`** verifies C2PA Content Credentials offline: who signed a file,
  what tool produced it, which AI model generated it (if any), the chain of
  edits back to the source, and whether the file carries a recognised neural
  watermark. The watermark cross-check spans six detector families:
  silentcipher, AudioSeal, and WavMark on audio, TrustMark-B on image,
  per-frame TrustMark with a temporal vote on video, and SynthID-text on text.
- **`provcheck-kit`** is the creator side: mint a signing cert, sign your media,
  and publish the cert fingerprint to your atproto DID, so downstream verifiers
  can confirm the signature came from the handle on the file.
- Both CLI binaries and the desktop GUI ship as pre-built downloads for Windows,
  Linux, and macOS. Detector weights download on demand, never automatically.
  Deepfake detection (asking whether a file is AI-generated with no watermark
  present) is a separate problem and is not shipped at any version; the
  `Detector` trait lets operators wire their own classifier as a bring-your-own
  model or a future paid DLC.

**The keyed forensic add-ons (BUSL-1.1, opt-in, never bundled into the
Apache-2.0 binary):**

- **Backfire** (in `backfire/`) is an imperceptible, keyed image watermark
  optimised to be a fixed point of AI provenance-stripping attacks, so running
  the stripper leaves the keyed identifier readable instead of erasing it.
  **Backfire 3.0** makes the mark a joint fixed point of two removers
  at once, a diffusion purifier and a learned neural codec, and survives the
  published removal tool behind the "invisible watermarks are provably
  removable" result (Zhao et al., arXiv:2306.01953) at 99.5% on the diffusion
  attack and 94 to 97.5% on the neural-codec attack across a 200-image set at
  30 dB (86.5% on the hardest iterated pass), with zero false positives over
  the 200 marked images and over 1,000 unmarked. It does not survive
  controllable regeneration from clean noise; the honest limit is documented
  in `backfire/LIMITS.md`.
- **provcheck-mellin** (in `crates/provcheck-mellin/`) is the opt-in
  Fourier-Mellin audio channel: a keyed, per-copy serial for leak attribution,
  under the same BUSL-1.1 model.

Both keyed tools convert to AGPL-3.0-or-later four years after each version's
first public distribution, integrate only across a process boundary
(`provcheck --backfire-read`, `provcheck --mellin-read`, and dedicated desktop
tabs), and require the user's own key.

Why the split: the verifier and creator kit are Apache-2.0 because provenance is
only worth anything if anyone can check it, freely and offline. The keyed marks
are BUSL-1.1 — source-available and reproducible, free for non-commercial use,
commercially licensed otherwise — because keeping a watermark ahead of the tools
built to remove it is continuous research, and the commercial licence is what
funds that research. The four-year Change Date means each version becomes fully
open in time: the licence buys the runway to keep the marks working as the attacks
improve, not a permanent enclosure.

The full version-by-version history is in [Release history](#release-history)
below.

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
Bundles are currently unsigned — Gatekeeper / SmartScreen will warn on
first launch.

Intel Mac users: run the Apple Silicon binary through Rosetta, or use
`cargo install` below.

### Via cargo (any platform with a Rust toolchain)

Install pinned to a release tag, straight from this repo:

```bash
cargo install --locked --git https://github.com/CreativeMayhemLtd/provcheck \
    --tag v1.4.0 provcheck-cli              # verifier
cargo install --locked --git https://github.com/CreativeMayhemLtd/provcheck \
    --tag v1.4.0 provcheck-kit              # signing kit
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

### In a Docker container (e.g. for a render pipeline)

```dockerfile
FROM debian:bookworm-slim
ARG PROVCHECK_VERSION=vX.Y.0
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /tmp/kit.tar.gz \
    "https://github.com/CreativeMayhemLtd/provcheck/releases/download/${PROVCHECK_VERSION}/provcheck-kit-${PROVCHECK_VERSION}-linux-x86_64.tar.gz" \
 && tar -xzf /tmp/kit.tar.gz --strip-components=1 -C /usr/local/bin/ \
 && rm /tmp/kit.tar.gz
```

### Build dependencies

The pre-built release tarballs are self-contained except for one
runtime shared library — `libpcsclite1` — that the YubiKey support in
`provcheck-sign` links unconditionally even if you never plug in a
YubiKey. Without it the binary segfaults at start on a minimal Linux
image.

If you `cargo install` from source instead, you'll also need a small
set of build-time packages. The Linux lists below assume Debian /
Ubuntu (apt) and Fedora / RHEL (dnf); other distros have equivalent
packages.

**Build-time (Debian/Ubuntu):**

```bash
apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcsclite-dev \
    libdbus-1-dev \
    ca-certificates git
```

**Build-time (Fedora/RHEL):**

```bash
dnf install -y \
    pkgconf-pkg-config \
    openssl-devel \
    pcsc-lite-devel \
    dbus-devel \
    ca-certificates git
```

**Runtime (any Linux):**

```bash
# Debian/Ubuntu
apt-get install -y libpcsclite1
# Fedora/RHEL
dnf install -y pcsc-lite-libs
```

Why each:

| Package | Pulled in by | Used for |
|---|---|---|
| `pkg-config` | several `*-sys` crates | resolving native dep flags |
| `libssl-dev` | `openssl-sys 0.9.117` (transitive — `provcheck-sign`) | OpenSSL link. `c2pa` core uses `rust_native_crypto`, but `provcheck-sign` still pulls `openssl-sys` transitively; without `libssl-dev` cargo fails at `pkg-config --libs --cflags openssl`. |
| `libpcsclite-dev` (build) / `libpcsclite1` (runtime) | `yubikey` crate via `provcheck-sign` | PC/SC smartcard interface for the YubiKey PIV backend. Linked unconditionally — even users who never touch a YubiKey need the runtime lib or the binary segfaults at start. |
| `libdbus-1-dev` | `keyring v3` Secret Service backend | OS keyring on Linux (`provcheck-kit init` default backend). |
| `ca-certificates`, `git` | cargo + HTTPS | only needed for `cargo install --git`. |

macOS and Windows builds don't need the apt list — the equivalent
libraries ship in the OS (Keychain, PC/SC) or are vendored.

> **Planned:** feature-gate
> `provcheck-sign`'s `openssl-sys` dependency so the workspace
> consistently uses `rust_native_crypto` / `rustls`. That would let us
> drop `libssl-dev` and the corresponding OpenSSL CVE-tracking burden
> from the deployment surface.

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

A `--require-watermark` run passes if at least one detector fires;
the families are independent, and a file marked by one typically
won't trigger the others.

Watermark detection runs across every shipped family, dispatched by
modality: the three audio detectors (silentcipher, AudioSeal, and
WavMark) on audio, TrustMark-B on images, per-frame TrustMark on
video, and SynthID-text on text.

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

## Watermark detection — what we ship

provcheck ships three fully-implemented neural-watermark detectors,
each in its own sibling crate (`provcheck-watermark`,
`provcheck-audioseal`, `provcheck-wavmark`). The verifier runs all
three on every audio input and reports each independently.

**silentcipher** is the audio watermark used by Doomscroll.FM and the
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

Robustness posture: provcheck is a detector, not a promise that a mark
is permanent. We measure our detection against deliberate
provenance-stripping and ordinary transcoding, and we hold ourselves to
the one invariant we never break (a stripped asset must never verify). See
[`docs/audio-watermark-survival-range.md`](./docs/audio-watermark-survival-range.md)
for survival against ordinary transcoding.

Power-user diagnostic tools (binary dump, cross-implementation diff,
sample-shift alignment) live in
[`crates/provcheck-watermark/examples/`](./crates/provcheck-watermark/examples/).
They double as the regression suite — running them against a
Python reference will catch any future symphonia / tract / model
upgrade that would reopen the v0.3.3 LAME-trim gap.

## Supported formats

Whatever the upstream [`c2pa` crate](https://crates.io/crates/c2pa)
supports — currently WAV, MP3, JPEG, PNG, HEIC, AVIF, WebP, MP4, MOV.
The crate's format list is authoritative.

Watermark detection runs by modality: audio (silentcipher, AudioSeal, and WavMark), image and video (TrustMark-B), and text (SynthID-text).

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
  [Doomscroll.FM](https://doomscroll.fm) pipeline,
- works on ANY C2PA-signed content, not just ours.

## Release history

| Version | Date | Highlights |
|---|---|---|
| **v1.4.0** | 2026-08-31 | Backfire image mark validated at scale on a 200-image corpus: the keyed serial survives diffusion regeneration 99.5%, neural-codec re-encode 94 to 97.5% (the hardest iterated case holds 86.5%), and benign JPEG, resize, and blur 97 to 99%, with zero false positives over the 200 marked images and a separate 1,000 unmarked. Honest limit unchanged: no survival against controllable regeneration from clean noise. A free, Apache-2.0 **ComfyUI node** also lands: one node to watermark and C2PA-sign a generated image, audio, or video inside the graph, or verify a mark; and the Backfire image embed gains content-adaptive perceptual masking for lower-visibility marks. Docs trimmed to shipped reality; no verifier, kit, or wire-format changes. |
| **v1.3.0** | 2026-08-28 | Backfire 3.0: the keyed image mark (in `backfire/`, BUSL-1.1, never bundled into the Apache binary) becomes a fixed point of two AI regeneration attacks at once, a diffusion purifier and a learned neural codec, so both removers leave the keyed identifier readable. Validated against the public tool behind the "invisible watermarks are removable" result. The honest limit in `backfire/LIMITS.md`: no survival against controllable regeneration from clean noise. |
| **v1.2.0** | 2026-08-19 | Launch of Backfire, an imperceptible keyed image watermark that AI diffusion-stripping amplifies instead of removes. Wired as an experimental option (`provcheck --backfire-read` plus a desktop Backfire tab); the `provcheck-mellin` audio channel adopts the same BUSL-1.1 model. The desktop app gains a per-family Watermark scan selector plus a UX-audit polish batch. MSRV rises to 1.88. |
| **v1.1.0** | 2026-07-01 | Desktop app gains dedicated Watermark and Detect tabs; the shipped detector families become first-class surfaces, and top-bar external links open in the browser. A release-tag gate lands in `check-before-push.sh`: one `v*.*.0` tag per 24 hours, no force-rewrite of an already-published tag, and an FC-declaration file required before a minor tag. |
| **v1.0.0** | 2026-07-01 | First 1.0 release. Code-signing goes live: Authenticode-signed Windows binaries via SSL.com eSigner and detached minisign signatures on the Linux and macOS artifacts, verified fail-closed before publish. |
| v0.9.1 to v0.9.88 | 2026-06-29 | Pre-1.0 hardening line (iteration tags only): workspace test coverage expanded across every crate, operator-facing messages and docs corrected to shipped reality, SBOM generation and code-signing scaffolding, and dependency-advisory tracking. No wire-format or behavior changes. |
| **v0.9.0** | 2026-06-29 | Video and text modalities wired live: `provcheck-video` runs per-frame TrustMark-B with a temporal majority vote, and `provcheck-synthid-text` ships tournament-sampling detection for SynthID-marked text. ComfyUI stamping node lands; a CUDA execution-provider fallback diagnostic (issue #32); image-decode decompression-bomb hardening. |
| **v0.7.0** | 2026-06-28 | Multimodal expansion: image watermarking via Adobe and CAI's TrustMark-B (MIT code and weights) with full BCH ecosystem interop, video and text modality crates scaffolded, and `kit stamp`, a one-call watermark-plus-sign pipeline. Detector weights move to download-on-demand DLC, dropping the kit binary from about 143 MB to about 22 MB. |
| **v0.6.0** | 2026-06-28 | Throughput, memory, and GPU: chunk-parallel embed for a 4x CPU speedup, a `kit serve` batch worker, a streaming embed mode that caps peak RSS at 5 GB on a 56-minute stereo episode, and an opt-in CUDA backend for roughly 10x. |
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
