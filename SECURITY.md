# Security policy

## Reporting a vulnerability

Email **security@creativemayhem.com** with the subject line `provcheck security`.
Please do not open a public issue or pull request for a suspected
vulnerability — give us a chance to ship a fix before it becomes a
target.

Expect an acknowledgement within 72 hours. For severe issues we will
coordinate a disclosure timeline with the reporter; for low-severity
issues we typically fold the fix into the next regular release and
credit the reporter in the commit body (opt-out on request).

PGP / Signal / encrypted reporting on request.

## Supported versions

The latest published `vX.Y.0` tag on
[GitHub Releases](https://github.com/CreativeMayhemLtd/provcheck/releases)
is the only supported version. We don't maintain backport branches.
Earlier tags receive no security updates — if you're pinned to one,
upgrade to track the current release line.

Iteration tags (`vX.Y.Z` where Z > 0) land on the dev repo as
commit anchors during the pre-release coverage push and do not
have published GitHub Releases; they are not "supported" in any
form and are not intended for installation.

The release line is fast-moving by design (the project pre-dates
v1.0); a security fix landing on `main` becomes the next patch tag,
usually within 24 hours of the fix landing.

## Tolerated transitive advisories

Several `cargo audit` / Dependabot advisories appear against provcheck
that we cannot fix from this repository. They sit deep in transitive
dependency chains where the immediate upstream parent has not yet
migrated, or where no fixed version of the affected crate exists.
Rather than ignore them silently, this section documents each one
with our reasoning so contributors don't re-litigate them on every
audit pass.

Re-evaluate **the moment any of these get an upstream fix.** The
release-prep checklist runs `cargo audit` in both the workspace and
`app/src-tauri`; if any of the IDs below disappear from that output,
bump the affected dep and remove the corresponding row here in the
same commit.

### Workspace (`Cargo.lock`)

| ID | Crate | Severity | Path | Why tolerated |
|---|---|---|---|---|
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) | `rsa` 0.9.x | medium (5.9) | `c2pa` → `rsa` | Marvin Attack timing sidechannel. **No fixed version exists upstream.** Reachable only when verifying RSA-signed C2PA manifests; ECDSA / Ed25519 chains (the modal case, including everything `provcheck-kit` produces) are not affected. The `rsa` crate has acknowledged the issue but no fixed version has shipped — track the [advisory page](https://rustsec.org/advisories/RUSTSEC-2023-0071) for status changes. |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | `paste` 1.0.x | unmaintained | `tract-linalg` → `tract-core` → carried by `tract` deps still in the lockfile | Build-time procedural macro, no runtime surface. The image-modality decoder migrated from `tract` to `ort` in v0.7 phase 7b-followup, but `tract` is still pulled in transitively by other crates in the graph. Tract is preparing a replacement; we move when tract does, or the row drops if `tract` exits the workspace lockfile entirely. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370) | `proc-macro-error` | unmaintained | transitive via `tract` | Build-time, no runtime surface. Same fix path as RUSTSEC-2024-0436. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173) | `proc-macro-error2` | unmaintained | `age` → `i18n-embed-fl` → `provcheck-sign` | Build-time. The `age` crate uses `i18n-embed-fl` for localised error messages; we use age for at-rest encryption only (passphrase-protected ES256 keys), so the i18n surface is not load-bearing for us. Wait for `age` to either drop i18n-embed-fl or for i18n-embed-fl to migrate off proc-macro-error2. |
| [RUSTSEC-2026-0217](https://rustsec.org/advisories/RUSTSEC-2026-0217) | `tract-nnef` 0.21.10 | medium | `tract-nnef` → `tract-onnx` → `provcheck-{watermark,audioseal,wavmark}` | Integer overflow in the NNEF `.dat` tensor parser yields an out-of-bounds read on model load. Companion to the `tract-onnx` external-data path-traversal advisory ([GHSA-h668-6x6g-f8r5](https://github.com/advisories/GHSA-h668-6x6g-f8r5) / CVE-2026-55832), which has no RustSec ID and so is Dependabot-only. **A fix exists (tract 0.21.16 / 0.21.17) but is unresolvable in this graph**: `tract-linalg 0.21.17` caps `time < 0.3.42`, while `c2pa` → `serde_with 3.21+` (which fixes its own advisory) requires `time ~0.3.47`; the two fixes are mutually exclusive on `time`, so we keep the serde_with fix and tolerate this one (measured 2026-08-20; not an MSRV issue, MSRV is 1.88). **Not reachable at runtime:** both are model-LOAD advisories, and our audio detectors compile ONNX weights in via `include_bytes!` and hand tract a `&[u8]` slice, so no untrusted model file is ever parsed. The row drops when tract lifts its `time` cap or leaves the lockfile entirely (the ort migration is the endgame). |
| [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253) | `lru` 0.16.4 | unsound | `atrium-common` → atproto attestation stack | Unsoundness advisory (fixed in lru 0.18.2), pinned by `atrium-common 0.1.4`, which is already at its latest release. Unsound-classified, not a vulnerability with a demonstrated exploit path, and the lru use sits inside atrium's identity-resolution caching, fed by our own resolver flow rather than attacker-shaped keys. Bump lands automatically when atrium moves; re-check each audit pass. |
| [RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194) | `quick-xml` 0.39.x | high (7.5, availability) | `c2pa` → `quick-xml` | Quadratic-time duplicate-attribute checking: a crafted XMP packet whose start tag carries tens of thousands of attributes can stall the parsing thread for minutes to hours. **Reachable under untrusted input:** `verify()` calls `c2pa::Reader::from_file` (`crates/provcheck/src/verification.rs`), and c2pa parses a dropped file's embedded XMP through quick-xml before any claim validation, so the packet content is attacker-controlled. Availability-only, no integrity or confidentiality impact. **No upstream fix reachable:** even c2pa 0.89.0 (latest) and plist 1.9.0 still require `quick-xml ^0.39.x`, below the fixed 0.41.0; there is no c2pa or plist release on quick-xml 0.41 to bump to. In-product exposure is bounded: the CLI verifies one file per process (an operator interrupts a stall), and the GUI runs verify on a `spawn_blocking` thread. Downstream services that embed `provcheck::verify` over untrusted input should apply the "Verifying untrusted input in a service" guidance below until quick-xml clears upstream. |
| [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195) | `quick-xml` 0.39.x | high (7.5, availability) | `c2pa` → `quick-xml` | Unbounded heap allocation from XML namespace declarations in `NsReader` (roughly 3x the tag's byte size, no cap): a crafted XMP packet can drive the process to OOM. Same entry point, same attacker-controlled XMP, same availability-only scope, and same no-upstream-fix status as RUSTSEC-2026-0194 above. quick-xml 0.41.0 adds a 256-declarations-per-element default cap (`NamespaceResolver::set_max_declarations_per_element`); we inherit the fix the moment c2pa or plist bumps to it. |

**Dependabot-only advisories** (no RustSec ID, so not surfaced by `cargo audit`; tracked via GitHub Dependabot):

- **`glib`** ([GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g), medium) — unsoundness in the `Iterator` / `DoubleEndedIterator` impls for `VariantStrIter`. Fixed in 0.20.0. Transitive via the same Tauri `gtk-rs 0.18` stack described below; a major bump pinned by that generation, not runtime-reachable for us. Moves when the gtk stack moves.

### Tauri app (`app/src-tauri/Cargo.lock`)

The desktop GUI inherits everything above, plus a long tail of
unmaintained advisories from `tauri 2.x`'s transitive use of GTK3
on Linux. **The whole tail has a single root cause:** Tauri 2.x's
Linux backend (`wry` → `webkit2gtk`) is built on `gtk-rs 0.18`, and
the gtk-rs maintainers marked the GTK3 bindings unmaintained when
GTK4 became mainstream. Tauri's published migration path is wry's
gtk4 backend; we move when Tauri does.

The unmaintained advisories in this group:

- [RUSTSEC-2024-0411](https://rustsec.org/advisories/RUSTSEC-2024-0411) `gdkwayland-sys`
- [RUSTSEC-2024-0412](https://rustsec.org/advisories/RUSTSEC-2024-0412) `gdk`
- [RUSTSEC-2024-0413](https://rustsec.org/advisories/RUSTSEC-2024-0413) `atk`
- [RUSTSEC-2024-0414](https://rustsec.org/advisories/RUSTSEC-2024-0414) `gdkx11-sys`
- [RUSTSEC-2024-0415](https://rustsec.org/advisories/RUSTSEC-2024-0415) `gtk`
- [RUSTSEC-2024-0416](https://rustsec.org/advisories/RUSTSEC-2024-0416) `atk-sys`
- [RUSTSEC-2024-0417](https://rustsec.org/advisories/RUSTSEC-2024-0417) `gdkx11`
- [RUSTSEC-2024-0418](https://rustsec.org/advisories/RUSTSEC-2024-0418) `gdk-sys`
- [RUSTSEC-2024-0419](https://rustsec.org/advisories/RUSTSEC-2024-0419) `gtk3-macros`
- [RUSTSEC-2024-0420](https://rustsec.org/advisories/RUSTSEC-2024-0420) `gtk-sys`

The desktop GUI inherits both quick-xml advisories
(RUSTSEC-2026-0194 / -0195) from the workspace table above via its
`c2pa` → `provcheck` dependency, and it additionally resolves a
**second** vulnerable quick-xml, 0.38.4, via
`plist` → `tauri-utils` → `tauri`. That copy parses Tauri's own
config and macOS property lists at build and startup time, not
user-dropped media, so it is not an untrusted-input surface. It is
below the fixed 0.41.0 for the same reason: plist 1.9.0 (latest)
still requires `quick-xml ^0.39.2`, so there is no plist release to
bump to. Both copies clear when their respective upstreams
(`c2pa`, `plist`) move to quick-xml 0.41.

Plus a handful of unrelated unmaintained-only advisories carried by
deeper transitive deps:

- [RUSTSEC-2025-0057](https://rustsec.org/advisories/RUSTSEC-2025-0057) `fxhash` (via `selectors` via `kuchikiki` via `tauri-utils`)
- [RUSTSEC-2025-0075](https://rustsec.org/advisories/RUSTSEC-2025-0075) `unic-char-range` (via `selectors`)
- [RUSTSEC-2025-0080](https://rustsec.org/advisories/RUSTSEC-2025-0080) `unic-common` (via `selectors`)
- [RUSTSEC-2025-0081](https://rustsec.org/advisories/RUSTSEC-2025-0081) `unic-char-property` (via `selectors`)
- [RUSTSEC-2025-0100](https://rustsec.org/advisories/RUSTSEC-2025-0100) `unic-ucd-ident` (via `selectors`)
- [RUSTSEC-2025-0136](https://rustsec.org/advisories/RUSTSEC-2025-0136) `unic-ucd-version` (via `selectors`)
- [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097) `rand` 0.7.3 — unsoundness when callers install a custom logger and use `rand::rng()`. We do neither; the rand path here is `selectors` → `phf_codegen`, a build-time codegen helper.

All of the above are tracked-and-waiting-on-Tauri-2.x's-gtk4-move.
When the Tauri release that ships the gtk4 backend lands, bump the
Tauri dep, re-run `cargo audit`, and remove rows from this section
to match what actually cleared.

## Verifying untrusted input in a service

The two `quick-xml` advisories above (RUSTSEC-2026-0194 / -0195) are
availability-only and, until quick-xml clears upstream, cannot be
neutralised from inside the process. A library-level wall-clock
timeout does not help: Rust cannot cancel a running thread, so a
thread parked in the quadratic attribute scan keeps burning CPU
after the caller gives up, and the namespace-declaration
allocation still climbs toward OOM. There is also no input-size cap
we can apply cheaply, because c2pa parses the XMP packet internally
and we never see its boundary; a whole-file cap cannot distinguish a
legitimate hour-long MP3 from a small file carrying a pathological
XMP tag.

provcheck's own surfaces are bounded by their shape: the CLI reads
one file per process, so a stall is a single interrupted invocation,
and the GUI runs verify on a `spawn_blocking` thread against files
the local user chose to open. Neither is a network-facing,
unauthenticated endpoint.

If you build one — any service that calls `provcheck::verify` (or
c2pa directly) on files supplied by untrusted callers — do the
verification in a **short-lived child process** with a wall-clock
timeout and a memory limit (`ulimit -v` / `setrlimit(RLIMIT_AS)` on
Linux, a Job Object memory cap on Windows), and kill the child on
breach. Process isolation is the only mechanism that contains both
a runaway parse thread and its allocation while the fix waits on
upstream. Drop this guidance once the `quick-xml` rows clear.

## Update process

When `cargo audit` reports a NEW advisory ID that is not in the
table above:

1. Decide if a fix is reachable from this repo (direct dep bump,
   transitive bump via `cargo update -p <crate>`, or feature
   toggle).
2. If yes, fix it in the next patch release.
3. If no — document it here in the same commit that's adding it,
   with the same shape as the existing rows (ID, crate, severity,
   path, why tolerated, what fix path it waits on).

When an existing tolerated advisory clears (the rust-sec database
or upstream ships a fix, or the dep tree shifts to drop the
affected crate entirely):

1. Bump the relevant dep in `Cargo.toml` / `app/src-tauri/Cargo.toml`
   or run the appropriate `cargo update -p <crate>` to refresh the
   lockfile.
2. Re-run `cargo audit` in both `Cargo.lock` and
   `app/src-tauri/Cargo.lock` and confirm the ID is gone.
3. Remove the corresponding row from this file.
4. Ship the change as a patch release with the cleared ID called
   out in the commit body.

## Scope

provcheck is a signing + verification tool. The most security-
relevant surfaces are:

- `provcheck-sign` — private key custody (OS keychain or age-
  encrypted file). The age-file backend is the only place we write
  long-lived secret material to disk, and the keychain backend
  delegates custody entirely to the OS. Both backends use
  authenticated encryption / OS-level primitives; we never roll our
  own crypto.
- `provcheck-publish` — atproto session credentials in
  `session.json` (file mode 0600 where the OS supports it). The
  refresh JWT is the long-lived secret; access JWTs rotate every
  ~15 minutes.
- `provcheck-platform` — fetches `app.provcheck.signingKey` records
  over HTTPS to atproto PDSes. Cache lives under the platform-
  appropriate data dir; never executes downloaded content.
- The watermark detectors run ONNX inference via `ort`
  (onnxruntime 1.20 with the `load-dynamic` feature; the
  platform-specific CPU shared lib is bundled in the release
  archive). v0.7 phase 7b-followup migrated from `tract-onnx`
  to `ort` for the image-modality decoder; the audio detectors
  (silentcipher, AudioSeal, WavMark) followed in the same line.
- Detector weights ship as **download-on-demand DLC** from the
  `weights-v1` GitHub Release on the public mirror, NOT as
  `include_bytes!` blobs. This is the v0.8 phase 8a change that
  dropped the kit binary from ~143 MB to ~22 MB. The download +
  install flow:
  1. The kit binary embeds a compile-time `MANIFEST` table
     (`crates/provcheck-weights/src/manifest.rs`) of every
     weight: family name, variant name, file name, public-mirror
     URL, SHA256 hash, and expected size in bytes.
  2. On first detector call, `provcheck-weights::load_if_cached`
     looks for the weight in the platform cache dir
     (`dirs::cache_dir() / provcheck`). If missing, the verifier
     surfaces `Error::NotCached` and refuses to run; the operator
     installs via `provcheck-kit weights install <family>` which
     downloads to a tempfile, hashes it, compares to the MANIFEST
     SHA, and renames into the cache atomically only if the hash
     matches.
  3. On subsequent calls, the cached file is re-hashed against
     the MANIFEST entry before being handed to ort. A
     post-install bit-flip on disk surfaces as SHA mismatch and
     a clean error, not a silent substitution.
- **Model-substitution attack surface**: an attacker would need
  to either (a) compromise the binary's compile-time MANIFEST
  table (covered by the platform's binary-integrity story —
  GitHub-signed release artefacts on Windows / macOS, distro
  package signatures on Linux), or (b) produce a weight file
  that collides with the SHA-256 hash of a legitimate weight
  (computationally infeasible). The DLC delivery model does NOT
  introduce a new substitution surface beyond what the binary's
  integrity already covers.
- **Windows binary integrity**: Windows artefacts in a `v*.*.0`
  release are Authenticode-signed by an SSL.com OV code-signing
  certificate held by Creative Mayhem UG (haftungsbeschränkt).
  Signed binaries carry an RFC-3161 timestamp so signatures
  remain valid past the cert's expiry. Verification via
  `Get-AuthenticodeSignature` on the target machine; the signing
  chain terminates at SSL.com's Code Signing Intermediate CA
  RSA R1. Iteration tags (`vX.Y.Z`, `Z>0`) skip the release
  matrix and therefore skip signing — do not treat an iteration-
  tag download as a supported install. Full signing procedure
  in [`docs/release-process.md`](docs/release-process.md) §
  code-signing.

Things we explicitly do NOT do:

- Auto-update on the user's behalf.
- Phone home with usage telemetry.
- Send file content over the network. Verification is local;
  attestation queries send the creator's DID or handle to their
  PDS to fetch the signing-key record, nothing more.

If you find a way around any of these promises, that is a
security issue and we want to hear about it via the reporting
channel above.
