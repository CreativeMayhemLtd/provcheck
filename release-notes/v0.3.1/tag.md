v0.3.1: publisher attestation

Builds on v0.3.0's signing core. When a file already has a C2PA
manifest (e.g. signed by doomscroll.fm in production), the kit's
sign command now declares it as a parentOf ingredient on the new
claim and defaults the action to c2pa.published. The publisher's
atproto-attested signature joins the existing chain as a
derivative rather than as a parallel new claim.

Headline additions since v0.3.0:

* Auto-chain parent ingredients on re-sign — explicit lineage at
  the active-manifest level, not just in the manifest store.

* New SignAction (Created / Opened / Edited / Published) with
  CLI --action flag and GUI 4-radio picker. Default is
  auto-resolved from source provenance.

* Verifier exposes Report.parents — the chain rendered by the
  About card as "Originally from @creator.bsky.social ·
  Doomscroll.fm" rows alongside the publisher info.

* New kit_inspect_source Tauri command — lets the GUI inspect
  a dropped file's existing provenance before staging the sign.

* Release-ceremony script (scripts/publish_dc.sh).

Test surface: 201 across the workspace, zero failed.

Three binary surfaces ship: provcheck (verifier), provcheck-kit
(creator toolkit), provcheck-app (Sign + Verify GUI). All
CRT-static.

No wire-format breaks. v0.3.0 binaries continue to interoperate
with v0.3.1-signed files in both directions.
