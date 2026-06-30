# About provcheck

A comprehensive product brief — what provcheck is, what it does,
who it's for, and how it fits together. Source material for
[provcheck.ai](https://provcheck.ai) and a single-place orientation
for anyone touching the project.

## One-paragraph pitch

provcheck is an open-source desktop and command-line tool for
verifying — and producing — **C2PA Content Credentials** with a
creator identity bound to an atproto DID and a neural watermark
cross-check on top. Three independent provenance signals, one
verifier, every platform. It runs locally (files never leave your
machine), ships as a single binary plus a small GUI, and is
permissively licensed (Apache-2.0). It composes into other software
(rAIdio.bot, doomscroll.fm, third-party render pipelines) and
verifies any C2PA-signed content from any vendor — not just ours.

## What problem it solves

AI-generated content needs a trustable provenance signal or every
downstream ingester — archives, platforms, newsrooms, journalists,
search engines — has to guess what's real. [C2PA](https://c2pa.org)
is the open standard for the cryptographic half, backed by Adobe,
Microsoft, the BBC, and the major digital camera makers. Adobe's
`c2patool` and `contentcredentials.org` are the reference
implementations — useful tools, but neither is a cross-platform
desktop verifier you can ship inside other software, nor do they
include identity binding or watermark cross-check.

provcheck fills those gaps with a single workflow that says, in
plain language: "this file was signed by a key, that key belongs to
this person's atproto identity, and the audio carries a brand-stamp
from this generator." If all three line up, you have something
close to forensic-grade provenance. If they don't, the verifier
tells you which signal failed and why.

## The three signals — the core mental model

provcheck reports on three orthogonal claims about a file:

1. **Cryptographic signature (C2PA).** Does the file carry a valid,
   untampered C2PA manifest? Does the signing cert chain back to a
   trusted anchor?
2. **Identity attestation (atproto).** Has the signer published this
   cert fingerprint to their atproto DID? Is the bsky handle on the
   file really backed by the person who signed it?
3. **Neural watermark.** Six detector families ship live in v0.9:
   silentcipher + AudioSeal + WavMark on audio, TrustMark-B on
   images, per-frame TrustMark + temporal majority-vote on video,
   and Bayesian tournament-sampling z-score for SynthID-text on
   text. Does the file carry a brand-stamp embedded by a known
   generator at render time? Watermarks survive transcoding,
   lossy re-encode, and mild post-processing — so they show up
   even if someone strips the C2PA manifest.

These signals are independent. Any subset can pass or fail. A
reasonable file might be C2PA-signed but not attested (creator didn't
publish their cert). A doomscroll.fm clip might have silentcipher
detection but no C2PA signature yet (if the signing step isn't in
their render pipeline). The verifier shows what's there and what
isn't — no false binary verdicts.

## Two personas

**Verifiers** — journalists, archives, platforms, recipients,
automated ingest pipelines. Drag a file into the GUI or pipe it
through the CLI. Get a single page of structured truth.

**Creators** — anyone making content who wants their work trivially
re-verifiable. Mint an identity once, sign every file at render
time, publish your cert fingerprint to your bsky handle. The cost is
one CLI command per file (or one step in a render pipeline) and the
benefit is that every downstream verification works without anyone
having to manually look you up.

## What ships in every release

Six artifact families per release tag, with SHA-256 sidecars on
every file and CycloneDX 1.6 + SPDX 2.3 SBOMs on the binaries.
Thirty files per release in total:

```
provcheck-v<tag>-{linux-x86_64.tar.gz, macos-aarch64.tar.gz, windows-x86_64.zip}
provcheck-kit-v<tag>-{linux-x86_64.tar.gz, macos-aarch64.tar.gz, windows-x86_64.zip}
provcheck-gui-v<tag>-{x64-setup.exe, x64-en-US.msi, amd64.deb, amd64.AppImage, aarch64.dmg}
provcheck-v<tag>.{cdx.json, spdx.json}
provcheck-kit-v<tag>.{cdx.json, spdx.json}
```

Plus a `.sha256` sidecar for every file above. Available from the
[Releases page](https://github.com/CreativeMayhemLtd/provcheck/releases)
or via `cargo install provcheck-cli`.

## Install matrix

| Audience | Install path |
|---|---|
| End user (verifier, GUI) | Download the installer for your OS from the releases page. NSIS or MSI on Windows, `.deb` or `.AppImage` on Linux, `.dmg` on macOS-aarch64. |
| End user (verifier, CLI) | `cargo install provcheck-cli` or download the `provcheck-v<tag>-<platform>` archive. |
| Creator (sign + publish) | Download the `provcheck-kit-v<tag>-<platform>` archive. Full surface via `provcheck-kit --help`. |
| Render pipelines (Docker) | Pull the Linux tarball into a multi-stage Dockerfile. ~30-line setup. |
| Embedded in other tools | Apache-2.0 — `provcheck` is the verifier library, `provcheck-sign` + `provcheck-publish` are the signing libraries. CLIs are thin adapters. |

Intel Mac users: run the Apple Silicon binary through Rosetta, or
use `cargo install`. GitHub Actions has wound down their Intel macOS
runner capacity; aarch64-only for the foreseeable future.

## Verifier walkthrough — what the recipient sees

Drag a file into the GUI or run `provcheck <file>`. Output:

```
[VERIFIED]
  manifest: urn:c2pa:455a6826-3bfa-4d18-9359-9874dd824ce2
  signer: Doomscroll.fm
  attested by: @doomscroll.fm.bsky.social
[watermarks]
  silentcipher: detected — doomscroll.fm (72% confidence)
    payload: 44464d0100
  audioseal: not detected
  wavmark: not detected
[assertions]
  c2pa.actions.v2 = {"actions":[{"action":"c2pa.created","softwareAgent":"doomscroll.fm/3.0",...}]}
  com.doomscroll.broadcast = {"broadcast":"Doomscroll.fm",...}
```

Each section is independent: VERIFIED is the C2PA signature;
`attested by` is the atproto cross-check; the `[watermarks]` block
shows every detector's verdict. The detectors that ship live as
of v0.9 are silentcipher / AudioSeal / WavMark for audio,
TrustMark-B for images, per-frame TrustMark with temporal
majority-vote for video, and SynthID-text for text — each runs
independently and reports its own verdict. JSON output (`--json`)
emits a stable schema for ingestion pipelines.

Stricter modes turn each signal into a hard gate:

| Flag | Effect |
|---|---|
| `--require-trusted --trust-store roots.pem` | Cert chain must terminate at a trusted anchor. |
| `--require-attested` | Atproto attestation must succeed. |
| `--require-watermark` | A recognised neural watermark must be present. |

Exit code 0 = pass, 1 = fail, 2 = I/O error. Trivially CI-pipeable.

## Creator walkthrough — five minutes to "trivially re-verifiable"

```bash
# One-time setup (about five minutes)
provcheck-kit init                          # mint a fresh ES256 keypair
provcheck-kit login -u me.bsky.social       # attach an atproto identity
provcheck-kit publish                       # publish the cert fingerprint to atproto

# Every render after that
provcheck-kit sign mix.wav --embed-identity
```

Recipients run `provcheck mix.wav --auto-identity`. The embedded
`app.provcheck.identity` assertion auto-fills the cross-check — no
typing required. They see a VERIFIED stamp with the handle next to
it.

Lifecycle commands cover everything past the happy path: `list`
(every signing-key record under your DID), `revoke` (audit-
preserving tombstone), `rotate` (mint + publish + revoke atomically),
`export-backup` / `import-backup` (age-format encrypted backup with
optional X25519 recovery recipients). Keys live in your OS keychain
by default; `--age-file` switches to an age-encrypted file for
headless hosts.

Full walkthrough in [`docs/creator-workflow.md`](./creator-workflow.md).

## Integration patterns

**Render pipelines (Docker).** Pull the Linux binary into a multi-
stage container:

```dockerfile
FROM debian:bookworm-slim
# Pin to a specific release tag (see the public Releases page).
# Bump deliberately; do NOT use `latest` in production builds.
ARG PROVCHECK_VERSION=vX.Y.0
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -L "https://github.com/CreativeMayhemLtd/provcheck/releases/download/${PROVCHECK_VERSION}/provcheck-kit-${PROVCHECK_VERSION}-linux-x86_64.tar.gz" \
  | tar -xzf - --strip-components=1 -C /usr/local/bin/
```

Replace `vX.Y.0` with a real tag from
[the Releases page](https://github.com/CreativeMayhemLtd/provcheck/releases).
We pin in the example rather than chase `latest` because a render
pipeline that silently auto-upgrades the kit can shift watermark
parameters under you (e.g. the v0.5.2 SDR-default change).

At render time:

```bash
provcheck-kit sign /path/to/output.wav --embed-identity --action created
```

**CI verification gate** — make signed output a build requirement:

```bash
provcheck --quiet --require-trusted --trust-store roots.pem rendered.wav || {
  echo "rendered file failed C2PA verification — aborting publish"; exit 1
}
```

**Already in production with provcheck**:

- [rAIdio.bot](https://store.steampowered.com/app/4600000) signs
  every music render at output time.
- doomscroll.fm signs voice mixdowns (full C2PA + atproto identity)
  and applies silentcipher watermarks to music renders.

## Trust model — what we prove, what we don't

**What "VERIFIED + attested" actually means.** The file's bytes match
the signer's hash; the signer's key signed the manifest; the cert
fingerprint matches what the bsky handle's atproto identity has
published. Three independent cross-checks, all green. That's much
stronger than any single signal alone.

**What it does not mean.** It doesn't mean the content inside the
file is "true" or "accurate" — provcheck is about provenance (who
made this), not truth (is what they said true). It also doesn't mean
the creator's underlying identity is who they claim to be at a
passport-document level; that's a separate problem orthogonal to
cryptographic provenance.

**What an unsigned file means.** It means nobody using provcheck has
stamped this file. The content might still be authentic; it just
doesn't carry the signal. provcheck reports `[UNSIGNED]` and exits 1
— it does NOT claim "fake."

**What a watermark detection means.** The file's bytes carry a
recognised brand-stamp embedded by a known generator at render
time. Six detector families ship live in v0.9: silentcipher /
AudioSeal / WavMark on audio, TrustMark-B on images, per-frame
TrustMark + temporal majority-vote on video, and Bayesian
tournament-sampling z-score for SynthID-text on text. Audio +
image watermarks survive lossy re-encoding (codec, bitrate,
mild post-processing) — so the signal shows up even when C2PA
has been stripped. Each detector reports its own confidence;
the canonical thresholds are `Detected >= 0.70`, `Degraded ∈
[0.50, 0.70)`, `NotDetected < 0.50` (per
`provcheck::confidence`). Confidence < 0.50 is ambiguous and
the verifier reports NotDetected.

## Architecture mental model

```
                    +----- C2PA layer -----+
   FILE ----------> | manifest + signature | -- cryptographic verdict
                    +----------------------+
                              |
                              v
                    +-- atproto layer ----+
                    | cert.fingerprint vs |
                    | <handle>'s          | -- identity verdict
                    | signingKey records  |
                    +---------------------+
                              |
                              v
                    +-- watermark layer --+
                    | silentcipher /      |
                    | AudioSeal /         |
                    | WavMark / TrustMark | -- brand verdicts
                    | image+video /       |    (one per family)
                    | SynthID-text        |
                    +---------------------+
                              |
                              v
                    +---- Report ----+
                    | structured     |
                    | three-line     |
                    | verdict (JSON  |
                    | + human text)  |
                    +----------------+
```

Three independent layers. The CLI and GUI are thin adapters over
the verifier library; any consumer (third-party app, server, browser
extension) can call the library directly. The signing side is the
mirror — three libraries (sign, publish, attestation-spec) and a
thin CLI on top.

## Differentiation

| | provcheck | c2patool (Adobe) | contentcredentials.org |
|---|---|---|---|
| C2PA verify | yes | yes | yes |
| C2PA sign | yes (`provcheck-kit`) | yes | no (verify only) |
| Local-only (no upload) | yes | yes | no (web upload) |
| Cross-platform desktop GUI | yes (Win/Mac/Linux) | no (CLI only) | no (web only) |
| atproto identity binding | yes | no | no |
| Neural watermark detection | yes (six families live: silentcipher / AudioSeal / WavMark on audio, TrustMark-B on image + video, SynthID-text on text) | no | no |
| Bundleable inside other tools | yes (Apache-2.0, single binary) | yes (Apache-2.0) | no |
| SBOMs ship by default | yes | no | n/a |
| Open spec for the identity binding | yes ([`docs/atproto-signing-key.md`](./atproto-signing-key.md)) | n/a | n/a |

We don't compete with Adobe's tooling — we extend it. `provcheck`
uses the upstream `c2pa` Rust crate (Adobe's content-authenticity-
initiative project) for the cryptographic layer. The differentiation
is everything *around* that core: the identity layer, the watermark
layer, the desktop GUI, the in-process libraries, the supply-chain
transparency.

## Open source posture

- **Apache-2.0**, end to end. No CLA. No proprietary core.
- **Watermark detectors must be FOSS-license-compatible** — both
  code AND model weights. Permissive licences only
  (MIT / Apache-2.0 / BSD / ISC / CC0). CC-BY-NC, research-only,
  "community license" variants are not accepted. Full policy +
  per-detector survey in
  [`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md).
- **SBOMs in every release.** CycloneDX 1.6 + SPDX 2.3 per binary.
  Tooling-ready for Dependency Track, Trivy, Grype, Snyk, GitHub
  Advanced Security — every supply-chain scanner that speaks either
  format. Full docs in [`docs/sbom.md`](./sbom.md).
- **Atproto identity binding is openly specced.** Wire format,
  fingerprint algorithm, verification flow, lifecycle, trust
  caveats — [`docs/atproto-signing-key.md`](./atproto-signing-key.md)
  is sufficient for an outside developer to implement either side.
  The lexicon (`app.provcheck.signingKey`) is open for community
  adoption; we'll submit to lexicon.community once the wire format
  has soaked.
- **Public mirror discipline.** Development happens in a private dev
  repo with branch-protected CI; releases are curated snapshots
  pushed to the public mirror. Every release is reviewed by a human
  before it ships.

## Supply chain — SBOMs in detail

Every release since v0.3.6 ships per-binary SBOMs in two formats:

| File | Format | Standard | Tooling input |
|---|---|---|---|
| `provcheck-<tag>.cdx.json` | CycloneDX 1.6 | OWASP | Dependency Track, Snyk, Trivy, OWASP DT |
| `provcheck-<tag>.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 | Compliance, procurement, GitHub Advanced Security |
| `provcheck-kit-<tag>.cdx.json` | CycloneDX 1.6 | OWASP | (same) |
| `provcheck-kit-<tag>.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 | (same) |

We ship both formats because some consumers strongly prefer one or
the other — most modern scanners want CycloneDX, while compliance
teams typically ask for SPDX in vendor questionnaires. Marginal cost
is minimal; both come from one `cargo-sbom` invocation against the
same `Cargo.lock`.

Reproducible locally via:

```bash
cargo install cargo-sbom
./scripts/generate-sbom.sh v0.3.6 my-out-dir
```

Full rationale, consumption recipes for the common scanners, and
caveats about what the SBOM does NOT cover (toolchain, system libs,
model weights) in [`docs/sbom.md`](./sbom.md).

## Release history

| Version | Date | Highlights |
|---|---|---|
| **v0.3.7** | 2026-06-18 | Chunked watermark inference — fixes ~25 GB RSS blowup on multi-minute MP3s. Caps peak memory at ~1.5 GB regardless of audio length. |
| v0.3.6 | 2026-06-16 | SBOMs land — every release ships CycloneDX 1.6 + SPDX 2.3 per binary. Release script hardened against transient GitHub API 502s. |
| v0.3.4 | 2026-06-16 | Docs sweep + GUI bundle naming fix. New `docs/creator-workflow.md`. |
| v0.3.3 | 2026-06-16 | silentcipher detector accuracy fix — honors MP3 LAME encoder delay. Diagnostic harness (`decode_dump` / `decode_diff` / `align_check`) + Python reference dump. |
| v0.3.2 | 2026-06-15 | Responsive verify UI (async + spawn_blocking). GUI watermark toggle. |
| v0.3.1 | 2026-06-14 | Publisher-attestation flow — `kit sign` on an already-signed file auto-chains as a derivative. |
| v0.3.0 | 2026-06-14 | Full creator side: `provcheck-kit` + GUI Sign tab + `app.provcheck.identity` assertion + auto-bust attestation cache. |
| v0.2.0 | 2026-06-10 | silentcipher detector live. Multi-detector slot scaffolded. GUI attestation parity. |
| v0.1.0 | 2026-06-04 | CLI + library on crates.io. Release binaries Win/Mac/Linux. Initial Tauri GUI. |

Per-release commit + tag notes in
[`release-notes/`](../release-notes/).

## Roadmap

- **Tauri GUI SBOM** — npm/Vite frontend tree merged with the Rust-
  side tree. Local generation works today; CI-emitted combined SBOM
  is next.
- **SLSA L3 provenance** — Sigstore-signed SBOMs and build-provenance
  attestations. Currently we ship SHA-256 sidecars; full SLSA is the
  next supply-chain hardening tier.
- **More watermark detectors live** — AudioSeal and WavMark scaffolds
  exist in the repo as Vec slots inside the report; awaiting
  permissively-licensed model weights for both.
- **Image / video neural watermarks** — silentcipher is audio-only.
  Image-side equivalents (Truepic-style hashes, ImageNet-trained
  watermark detectors) are an open question; we won't ship something
  we can't FOSS-license.
- **`lexicon.community` submission** — the `app.provcheck.signingKey`
  and `app.provcheck.identity` lexicons get submitted to the
  community registry once the wire format has soaked. DNS TXT record
  at `_lexicon.provcheck.ai` planned alongside.
- **Standalone lexicons repo** — current lexicons live inside the
  provcheck repo. Eventually they get spun out so non-provcheck
  implementations can pull a single canonical source.
- **Hardware-backed key custody** — Yubikey / Secure Enclave / TPM
  integration via the `KeyProvider` trait we already shipped. Not
  blocked on anything; waiting for the first creator to ask.
- **EV code signing for desktop bundles.** SSL.com cert is the next
  signing-side hardening. Until then, GUI bundles trigger
  SmartScreen / Gatekeeper warnings on first launch.

## Brand context and authorship

provcheck is maintained by **[Creative Mayhem UG](https://creativemayhem.com)**,
a Berlin studio. Contact: [info@rAIdio.bot](mailto:info@rAIdio.bot).
Website: [provcheck.ai](https://provcheck.ai).

provcheck is the verification and identity layer underneath two
adjacent products:

- **[rAIdio.bot](https://store.steampowered.com/app/4600000)** —
  local-first AI music generation studio. Every render is
  C2PA-signed; provcheck is bundled.
- **doomscroll.fm** — autonomous AI-generated satirical news
  broadcast. Every clip is C2PA-signed at source; voice mixdowns
  carry the full provcheck identity assertion; music renders carry
  silentcipher watermarks.

A third tool (vAIdeo.bot) is in development.

## Standards we extend, not compete with

- The **C2PA standard** itself is developed by the
  [Coalition for Content Provenance and Authenticity](https://c2pa.org).
- The upstream **`c2pa` Rust crate** that does the heavy lifting is
  maintained by Adobe's
  [Content Authenticity Initiative](https://contentauthenticity.org).
- **atproto** is a federated identity protocol from
  [Bluesky](https://bsky.app).
- **silentcipher** is an open-research audio watermark; we ship the
  FOSS-licensed model weights.
- **CycloneDX** is maintained by [OWASP](https://owasp.org).
- **SPDX** is an ISO/IEC standard maintained by the
  [Linux Foundation](https://www.linuxfoundation.org).

We don't compete with any of them. We compose them into a single
tool that does the verifier-side and creator-side work end-to-end,
locally, with one install.

## Suggested website information architecture

If this brief is the input to a provcheck.ai rewrite, here's how it
splits cleanly into pages or landing-page blocks:

- **Landing page** — one-paragraph pitch, the three-signals diagram,
  download buttons for Win/Mac/Linux GUI + CLI, "Try it" with two
  example commands.
- **/verify** — the verifier story. Walkthrough screenshots, exit
  codes, integration into CI / scripts.
- **/create** — the creator story. Five-minute setup, full lifecycle
  commands, integration patterns (Docker, render pipelines), the
  trust-model section.
- **/spec** — the open spec for the atproto identity binding (lift
  [`docs/atproto-signing-key.md`](./atproto-signing-key.md) wholesale).
- **/security** — SBOMs, watermark license policy, public mirror
  discipline, what we prove vs what we don't.
- **/download** — the install matrix. Direct links per platform per
  binary type.
- **/releases** — release history table + per-release notes. Lift
  the table above; link each row to the corresponding GitHub release
  page.
- **/about** — Creative Mayhem, rAIdio.bot context, the
  C2PA / atproto / silentcipher / OWASP / SPDX heritage.

Eight pages of solid content from material that already exists in-
repo. The landing page is the only one that needs new copywriting;
everything else can be drafted directly from this doc plus
[`README.md`](../README.md),
[`docs/creator-workflow.md`](./creator-workflow.md),
[`docs/atproto-signing-key.md`](./atproto-signing-key.md),
[`docs/sbom.md`](./sbom.md), and
[`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md).
