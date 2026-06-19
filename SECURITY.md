# Security policy

## Reporting a vulnerability

Email **chris@neitzert.com** with the subject line `provcheck security`.
Please do not open a public issue or pull request for a suspected
vulnerability — give us a chance to ship a fix before it becomes a
target.

Expect an acknowledgement within 72 hours. For severe issues we will
coordinate a disclosure timeline with the reporter; for low-severity
issues we typically fold the fix into the next regular release and
credit the reporter in the commit body (opt-out on request).

PGP / Signal / encrypted reporting on request.

## Supported versions

The latest published `v0.4.x` tag on
[GitHub Releases](https://github.com/CreativeMayhemLtd/provcheck/releases)
is the only supported version. We don't maintain backport branches.
Earlier tags receive no security updates — if you're pinned to one,
upgrade to track the current release line.

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
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | `paste` 1.0.x | unmaintained | `tract-linalg` → `tract-core` → all `tract-onnx` consumers | Build-time procedural macro, no runtime surface. Tract is preparing a replacement; we move when tract does. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370) | `proc-macro-error` | unmaintained | transitive via `tract` | Build-time, no runtime surface. Same fix path as RUSTSEC-2024-0436. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173) | `proc-macro-error2` | unmaintained | `age` → `i18n-embed-fl` → `provcheck-sign` | Build-time. The `age` crate uses `i18n-embed-fl` for localised error messages; we use age for at-rest encryption only (passphrase-protected ES256 keys), so the i18n surface is not load-bearing for us. Wait for `age` to either drop i18n-embed-fl or for i18n-embed-fl to migrate off proc-macro-error2. |

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
- The watermark detectors run pure-Rust ONNX inference via
  `tract-onnx` against ONNX files embedded into the binary at
  compile time (`include_bytes!`). No runtime model loading from
  disk or network; no opportunity for model-substitution attacks
  against a deployed binary.

Things we explicitly do NOT do:

- Auto-update on the user's behalf.
- Phone home with usage telemetry.
- Send file content over the network. Verification is local;
  attestation queries send the creator's DID or handle to their
  PDS to fetch the signing-key record, nothing more.

If you find a way around any of these promises, that is a
security issue and we want to hear about it via the reporting
channel above.
