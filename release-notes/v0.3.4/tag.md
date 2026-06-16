v0.3.4: docs sweep + GUI bundle naming fix

Maintenance release. README rewritten to current v0.3.x state with a
release-history anchor for the website rewrite. New
docs/creator-workflow.md walks first-time creators end-to-end through
mint → publish → sign → cross-verify. docs/v0.3.3-detection-gap/
reframed as the durable regression harness.

GUI bundles drop the redundant inner version segment: Tauri-side
files in lockstep with the workspace, and the workflow rename step is
now version-agnostic so future drift can't reintroduce the wart.

No CLI behaviour or wire-format changes.
