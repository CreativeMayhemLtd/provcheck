v0.3.2: responsive UI during slow verify

Closes the "GUI window goes (Not Responding) on verify" complaint
without changing detection behaviour.

* verify_file Tauri command is now async + spawn_blocking. The
  silentcipher inference still takes ~100s on a typical input,
  but Windows no longer tags the window as not-responding —
  the spinner animates, dragging works, the result arrives
  cleanly when ready.

* GUI watermark toggle. New "Run watermark detection" checkbox
  in the identity bar, default ON, persisted. Users who only
  care about the C2PA signature can flip it off and verifies
  complete in under a second.

* GUI installer bundle naming. Bundles now named
  provcheck-gui-v0.3.2-*.{exe,msi,deb,AppImage,dmg} so they sort
  alphabetically with the CLI artefacts on the GitHub release
  page instead of falling below the "Show all N assets" fold.

A windowed-inference optimisation was attempted and reverted
after empirical testing showed it broke detection on low-SNR
files. Diagnostic examples that drove that decision ship with
the commit for future use.

A pre-existing accuracy gap remains between the Rust and Python
silentcipher decoders (Rust reports lower per-tile confidence
on the same input). Not a v0.3.2 regression — present in
v0.3.0 and v0.3.1 too. Tracked separately.

201 tests across the workspace, zero failed.

No wire-format breaks. v0.3.0 and v0.3.1 binaries continue to
interoperate with v0.3.2-signed files in both directions.
