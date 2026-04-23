# provcheck

**Download:**
[Windows](https://github.com/CreativeMayhemLtd/provcheck/releases) ·
[Linux](https://github.com/CreativeMayhemLtd/provcheck/releases) ·
[Apple](https://github.com/CreativeMayhemLtd/provcheck/releases) ·
[Source](https://github.com/CreativeMayhemLtd/provcheck/archive/refs/heads/main.zip)

*(Binary releases are coming with Milestone 4 — see [Status](#status).
Until then the platform links land on the Releases page, source archive is live now.)*

---

**Verify C2PA Content Credentials on any file, from any vendor, on any platform.**

`provcheck` is a free, open-source, offline desktop + command-line
verifier for [C2PA](https://c2pa.org) — the open provenance standard
backed by Adobe, Microsoft, the BBC, and major digital camera
manufacturers. Point it at a file and it tells you:

- whether the file carries a valid C2PA manifest,
- who signed it,
- what tool produced it,
- which AI model generated it (if any),
- the full chain of edits / ingredients back to the source.

No account. No web upload. No vendor lock-in. The file stays on your
machine.

## Status

**Milestone 1 in progress.** Repo scaffold landing; core verification
wiring + fixture tests next. See the [milestones section](#milestones)
below for the full roadmap.

## Install

### Pre-built binaries (Stage 1, coming soon)

Download the matching archive from the [Releases page](https://github.com/CreativeMayhemLtd/provcheck/releases)
or grab it directly from [provcheck.ai](https://provcheck.ai) and unpack:

- Windows — `provcheck-<version>-windows-x86_64.zip`
- macOS — `provcheck-<version>-macos-{x86_64,aarch64}.tar.gz`
- Linux — `provcheck-<version>-linux-x86_64.tar.gz`

### GUI app (Stage 1, coming soon)

Desktop installer with drag-and-drop verification.

- Windows — NSIS installer
- macOS — notarised `.dmg`
- Linux — `.deb` + `.AppImage`

### From source

```bash
git clone https://github.com/CreativeMayhemLtd/provcheck.git
cd provcheck
cargo build --release -p provcheck-cli
./target/release/provcheck <file>
```

## Try it

Two example signed files ship with the repo — a rAIdio.bot music
clip and a Doomscroll.fm video bumper. Both verify cleanly:

```bash
provcheck examples/rAIdio.bot-sample.mp3
provcheck examples/doomscroll.fm-sample.mp4
```

See [`examples/README.md`](./examples/README.md) for what's in each
sample and how they're signed.

## Use

Human-readable:

```bash
provcheck my-song.wav
```

Machine-readable (stable JSON schema — matches `provcheck_core::Report`):

```bash
provcheck --json my-song.wav
```

Silent pipeline mode (exit code only):

```bash
if provcheck --quiet my-song.wav; then
  echo "signed + verified"
fi
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | File carries a valid C2PA manifest that verified. |
| `1` | File is unsigned, or its manifest is invalid / tampered. |
| `2` | I/O error, unreadable file, or internal error. |

## Supported formats

Whatever the upstream [`c2pa` crate](https://crates.io/crates/c2pa)
supports. At the time of writing: WAV, MP3, JPEG, PNG, HEIC, AVIF,
WebP, MP4, MOV. The crate's format list is authoritative — we track
it.

## Why this exists

AI-generated content needs a trustable provenance signal or every
downstream ingester (archives, platforms, newsrooms, journalists) has
to guess. C2PA is the open standard that delivers it. Adobe has a
developer-facing CLI (`c2patool`) and a web verifier
(`contentcredentials.org`) — useful tools, but neither is a polished
cross-platform desktop app you can ship with other software or point
a non-technical recipient at.

`provcheck` fills that gap. It:

- runs locally (privacy-preserving — files never leave your machine),
- ships as a single binary,
- is free and permissively licensed (Apache-2.0),
- is bundled with [rAIdio.bot](https://store.steampowered.com/app/4600000)
  (and, later, vAIdeo.bot) so every output those tools produce is
  trivially re-verifiable by recipients,
- works on ANY C2PA-signed content, not just ours.

## Milestones

| # | Deliverable | Status |
|---|---|---|
| 1 | Workspace scaffold + `provcheck-core` crate + fixtures | In progress |
| 2 | `provcheck-cli` with human + JSON output, integration tests | Pending |
| 3 | Tauri GUI (drag-drop verifier) | Pending |
| 4 | CI + GitHub Releases for Win/Mac/Linux | In progress (workflows landed, first tagged release pending) |
| 5 | Bundle CLI inside rAIdio.bot `tools/` + `build.ps1` gate | Pending |
| 6 | Website download page + vAIdeo.bot bundling | Deferred |

## Contributing

Early-stage. Issues and PRs welcome once the core is wired
(milestone 1-2). The intended design is: `provcheck-core` is the
canonical verifier — CLI and GUI are thin adapters over it. If
behaviour differs between CLI and GUI, that's a bug in the adapters,
not the core.

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
