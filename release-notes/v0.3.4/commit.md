v0.3.4: docs sweep + GUI bundle naming fix

Maintenance release. No CLI behaviour or wire-format changes;
v0.3.3's MP3 detection fix continues to do the heavy lifting.

Docs

The README was still labelled v0.1.0 and described the GUI as "coming
soon" — four production releases out of date. Rewritten to reflect the
current state: CLI + GUI ship for Windows, Linux, macOS-aarch64; the
creator-side toolkit (provcheck-kit) is production-ready and battle-
tested against rAIdio.bot and doomscroll.fm. Added a release-history
table that anchors the v0.3.x story in one place so the website
rewrite has a single source to lift from.

New: docs/creator-workflow.md — end-to-end guide for `kit init →
login → publish → sign`, lifecycle commands (`list`, `revoke`,
`rotate`), backup / restore via age, and integration patterns for
Docker pipelines and ComfyUI nodes. Targets a creator who's never
used the tool before; assumes nothing beyond an atproto handle.

Updated: docs/v0.3.3-detection-gap/README.md gains a preamble framing
the directory as both the investigation record AND the regression
harness for any future change that could reopen the gap (symphonia
bump, tract upgrade, model swap, STFT change). The Python reference
is the load-bearing oracle; running the harness end-to-end is one
script invocation. The original investigation prose is preserved
below the new preamble.

GUI bundle naming

The Tauri app sits outside the main Cargo workspace (intentionally —
keeps frontend rebuilds from churning the CLI build), so it doesn't
pick up workspace version bumps automatically. v0.3.3's GUI bundles
were named `provcheck-gui-v0.3.3-provcheck-0.3.2-x64-setup.exe` and
similar: the workflow's rename step couldn't strip the literal
`provcheck_0.3.2_` prefix that Tauri's bundler emits because it was
matching against the (current) tag version, not whatever Tauri had
baked in.

Two-part fix:

1. Bumped `app/src-tauri/Cargo.toml`, `app/src-tauri/tauri.conf.json`,
   and `app/package.json` to 0.3.4 so they're in lockstep with the
   workspace this release.
2. Loosened the workflow's rename step (`.github/workflows/release.yml`)
   to strip ANY `provcheck_<X.Y.Z>_` prefix, not specifically the one
   matching the current tag. Belts and braces: if the Tauri files drift
   again in the future, the rename still produces clean names.

v0.3.4 GUI bundle names will be `provcheck-gui-v0.3.4-x64-setup.exe`,
`provcheck-gui-v0.3.4-amd64.AppImage`, etc. — the redundant inner
version segment is gone.

Test surface

193 workspace tests + 26 watermark unit tests + 6 integration tests,
all green. Validation matrix re-run against the bundled examples:

  examples/rAIdio.bot-sample.mp3   → [VERIFIED] signer: rAIdio.bot, exit 0
  examples/doomscroll.fm-sample.mp4 → [VERIFIED] signer: Doomscroll.fm, exit 0
  examples/unsigned-sample.mp3     → [UNSIGNED], exit 1

Wire format

No changes. Drop-in upgrade for any 0.3.x consumer.
