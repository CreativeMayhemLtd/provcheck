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

**v0.3.3 shipped 2026-06-16.** Both CLI binaries (`provcheck`,
`provcheck-kit`) and the desktop GUI ship as pre-built downloads for
Windows / Linux / macOS-aarch64. The creator-side flow (mint identity →
sign → publish to atproto → verifier cross-checks) is production-ready
and battle-tested against rAIdio.bot music renders and doomscroll.fm
voice mixdowns. The silentcipher watermark detector ships live and
agrees bit-exact with the Python reference on real-world MP3 inputs
(LAME encoder-delay handling fixed in v0.3.3).

## Install

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

Each archive carries a `.sha256` sidecar. Bundles are currently
unsigned — Gatekeeper / SmartScreen will warn on first launch.

Intel Mac users: run the Apple Silicon binary through Rosetta, or use
`cargo install` below.

### Via cargo (any platform with a Rust toolchain)

```bash
cargo install provcheck-cli         # verifier
cargo install --path crates/provcheck-kit   # signing kit (from source clone)
```

### In a Docker container (e.g. for a render pipeline)

```dockerfile
FROM debian:bookworm-slim
ARG PROVCHECK_VERSION=v0.3.3
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

provcheck runs the silentcipher neural watermark detector on every
audio input by default. The detector returns a payload (the embedded
brand identifier, e.g. `DFM\x01\x00` for doomscroll.fm) and a
confidence score; the brand classifier maps known payloads to known
brands.

```bash
provcheck my-song.mp3                    # detector runs (~few seconds)
provcheck --no-watermark my-song.mp3     # skip the detector
provcheck --require-watermark my-song.mp3 # exit 1 if no watermark
```

Detector runs only on audio inputs. Image and video paths skip it.

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
# One-time setup
provcheck-kit init                          # mint a fresh ES256 keypair
provcheck-kit login -u me.bsky.social       # attach an atproto identity
provcheck-kit publish                       # publish the cert fingerprint

# Sign + verify a file
provcheck-kit sign mix.wav --embed-identity
provcheck mix.wav --auto-identity           # verifies + cross-checks the atproto record
```

`provcheck-kit --help` shows the full command list. Headlines:

- **`init`** — mint a fresh ES256 keypair + cert.
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
  Linux), or in an age-encrypted file with optional recovery
  recipients for break-glass restore.
- **C2PA signing** — wraps the c2pa-rs builder with a sensible default
  manifest; pass `--manifest` for custom JSON.
- **Publisher-attestation re-sign** — sign a file that already carries
  a C2PA manifest and the kit auto-chains your signature on top as a
  derivative. Useful when a publisher attests an upstream creator's
  rendered output without losing the creator's provenance.
- **Atproto lifecycle** — full CRUD on signing-key records, with
  rotation primitives that keep the audit trail intact.

Full spec: [`docs/atproto-signing-key.md`](docs/atproto-signing-key.md).

## Watermark detection — what we ship

provcheck ships with one fully-implemented neural-watermark detector
(silentcipher) and scaffolds for two more (AudioSeal, WavMark) so
detectors can be added as siblings without reshaping the report.

**silentcipher** is the audio watermark used by doomscroll.fm and the
rAIdio.bot music pipeline. The detector runs the official silentcipher
ONNX decoder via tract, applies VCTK energy rescale + periodic-Hann
STFT, and decodes 21-symbol tiles into 5-byte brand payloads. Known
payloads are mapped to display names by the brand classifier (e.g.
`DFM\x01\x00` → "doomscroll.fm").

License posture: only watermark detectors with FOSS-compatible code
AND model weights are accepted. See
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
- is bundled with [rAIdio.bot](https://store.steampowered.com/app/4600000),
  the doomscroll.fm pipeline, and (next) a ComfyUI signing node,
- works on ANY C2PA-signed content, not just ours.

## Release history

| Version | Date | Highlights |
|---|---|---|
| **v0.3.3** | 2026-06-16 | silentcipher detector accuracy fix — honors MP3 LAME encoder delay + padding. Adds full Python reference + diagnostic harness (decode_dump / decode_diff / align_check). Structural Hann + always-pad alignments. |
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
