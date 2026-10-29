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
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) | `crypto-bigint` 0.5.5 | low | `c2pa` → `ecdsa` → `elliptic-curve` → `crypto-bigint` | Timing-variability in operations intended to be constant-time. Fixed in crypto-bigint 0.7.6, but reached only through `elliptic-curve 0.13.8` and `ecdsa 0.16.9`, the ECDSA stack that `c2pa 0.90.22` pins. crypto-bigint 0.7 requires elliptic-curve 0.14, which c2pa has not adopted, so there is no in-range bump. Same reachability class as the `rsa` row above: exercised only while verifying signatures on a local host, not against an attacker-controlled timing oracle. Re-evaluate when c2pa's ecdsa / elliptic-curve stack moves to crypto-bigint 0.7. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370) | `proc-macro-error` | unmaintained | `c2pa` → `static-iref` → `static-regular-grammar` | Build-time proc-macro, no runtime surface. Pulled by c2pa's `iref` / `static-iref` IRI-handling stack; the v1.5.0 tract 0.23 bump removed the older tract-stack path that also carried it. No fixed release of `proc-macro-error` exists; the row drops when `static-regular-grammar` migrates to `proc-macro-error2` or c2pa's iref chain updates. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173) | `proc-macro-error2` | unmaintained | `age` → `i18n-embed-fl` → `provcheck-sign` | Build-time. The `age` crate uses `i18n-embed-fl` for localised error messages; we use age for at-rest encryption only (passphrase-protected ES256 keys), so the i18n surface is not load-bearing for us. Wait for `age` to either drop i18n-embed-fl or for i18n-embed-fl to migrate off proc-macro-error2. |
| [RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374) | `basic-toml` 0.1.10 | unmaintained | `age` → `i18n-embed-fl` → `i18n-config` → `basic-toml` | Build-time only. Parses `i18n.toml` inside the `i18n-embed-fl` proc-macro that `age` uses for localized error strings (the same chain as the `proc-macro-error2` row). No runtime surface. Drops when i18n-config migrates off basic-toml or age drops i18n-embed-fl. |
| [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253) | `lru` 0.16.4 | unsound | `atrium-common` → atproto attestation stack | Unsoundness advisory (fixed in lru 0.18.2), pinned by `atrium-common 0.1.4`, which is already at its latest release. Unsound-classified, not a vulnerability with a demonstrated exploit path, and the lru use sits inside atrium's identity-resolution caching, fed by our own resolver flow rather than attacker-shaped keys. Bump lands automatically when atrium moves; re-check each audit pass. |
| [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371) / [-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370) / [-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372) | `zbus_names` / `zvariant` / `zvariant_derive` | unmaintained | Linux keyring (secret-service D-Bus) | Unmaintained advisories for the `zbus` D-Bus stack. Present in `Cargo.lock` but compiled only on Linux (the secret-service keyring backend); not in the Windows or macOS build tree (`cargo tree -i zbus_names` finds no path here). No fixed release. Drops when the keyring / zbus chain updates. |
| [RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367) / [-0368](https://rustsec.org/advisories/RUSTSEC-2026-0368) / [-0369](https://rustsec.org/advisories/RUSTSEC-2026-0369) | `zip` 8.6.0 | medium | `c2pa` → `zip` | Three filesystem-extraction advisories in `ZipArchive::extract` / `ZipStreamReader::extract`: a crafted archive can place symlinks whose targets escape the destination directory and have Unix permissions, including SUID/SGID bits, applied through them. **Fixed in zip 9.0.0 but unreachable here:** `c2pa` 0.90.22 pins `zip ^8.6.0` (verified: `cargo update -p zip --precise 9.0.0` fails to select a version), so no c2pa release on zip 9 exists to bump to. `zip` is pulled only by c2pa and is never called directly by provcheck; the vulnerable path is extraction-to-filesystem, which the verify and sign flows do not perform on caller-supplied input, and the symlink, SUID, and SGID vectors are Unix-only and moot on the Windows release target. Re-evaluate when c2pa moves to zip 9. |

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
- [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429) `glib` — unsoundness in the `VariantStrIter` iterator impls; same gtk-rs 0.18 family, reached only through the Linux GTK backend (`cargo tree -i glib` finds no build path on Windows/macOS).

Plus a handful of unrelated unmaintained-only advisories carried by
deeper transitive deps:

- [RUSTSEC-2025-0057](https://rustsec.org/advisories/RUSTSEC-2025-0057) `fxhash` (via `selectors` via `kuchikiki` via `tauri-utils`)
- [RUSTSEC-2025-0075](https://rustsec.org/advisories/RUSTSEC-2025-0075) `unic-char-range` (via `selectors`)
- [RUSTSEC-2025-0080](https://rustsec.org/advisories/RUSTSEC-2025-0080) `unic-common` (via `selectors`)
- [RUSTSEC-2025-0081](https://rustsec.org/advisories/RUSTSEC-2025-0081) `unic-char-property` (via `selectors`)
- [RUSTSEC-2025-0100](https://rustsec.org/advisories/RUSTSEC-2025-0100) `unic-ucd-ident` (via `selectors`)
- [RUSTSEC-2025-0136](https://rustsec.org/advisories/RUSTSEC-2025-0136) `unic-ucd-version` (via `selectors`)
- [RUSTSEC-2025-0098](https://rustsec.org/advisories/RUSTSEC-2025-0098) `unic-ucd-version` — a second unmaintained advisory for the same crate, reached via `urlpattern` → `tauri-utils`
- [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097) `rand` 0.7.3 — unsoundness when callers install a custom logger and use `rand::rng()`. We do neither; the rand path here is `selectors` → `phf_codegen`, a build-time codegen helper.

All of the above are tracked-and-waiting-on-Tauri-2.x's-gtk4-move.
When the Tauri release that ships the gtk4 backend lands, bump the
Tauri dep, re-run `cargo audit`, and remove rows from this section
to match what actually cleared.

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
