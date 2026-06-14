v0.3.1: publisher attestation — auto-chain parent ingredients

When the source file already carries a C2PA manifest (e.g. produced
by doomscroll.fm in production), the signing tool now declares it
as a parentOf ingredient on the new claim instead of producing a
parallel top-level signature. The publisher's atproto-attested
signature joins the existing provenance chain as a derivative.

Producer side (provcheck-sign + provcheck-kit + GUI):

* sign_asset reads the source via c2pa::Reader before signing.
  When the source has a manifest, the kit calls
  Builder::add_ingredient_from_stream with the source itself as a
  parentOf ingredient — making the lineage explicit at the
  active-manifest level. c2pa-rs would preserve the prior store
  either way, but explicit ingredient declaration is what
  renderers and verifiers walk.

* New SignAction enum (Created / Opened / Edited / Published) with
  default_action_for(provenance). Defaults to Published when the
  source carries prior provenance, Created when it doesn't —
  matching what a publisher most naturally wants to express.

* New CLI flag --action <created|opened|edited|published> (also
  accepts the canonical c2pa.<verb> form) for explicit override.

* GUI sign-preview state calls a new kit_inspect_source Tauri
  command on drop; when the source is signed, surfaces a
  "this file is already signed by X" notice plus a 4-radio
  action picker defaulted by the same default_action_for logic.
  Heading flips from "Ready to sign" to "Ready to publish" in
  that case to match the action semantics.

Verifier side (provcheck + GUI):

* New ParentManifest type and Report.parents: Vec<ParentManifest>.
  Each entry carries label / signer / claim_generator / title /
  embedded app.provcheck.identity claim when the parent was
  provcheck-attested.

* verification.rs walks the active manifest's parentOf ingredients
  and resolves them via reader.get_manifest(label). Bounded loop
  depth (max 8) so a pathological store with a cycle can't hang
  the verifier.

* About card renders parent entries as "Originally from
  @creator.bsky.social · Doomscroll.fm" rows alongside the
  existing publisher info, so a viewer of the final file sees
  the full attestation chain at a glance.

Versions bumped to 0.3.1 across Cargo workspace,
app/src-tauri/Cargo.toml, tauri.conf.json, and package.json.

Test surface: 201 unit + integration tests across the workspace
(up from 195 at v0.3.0), zero failed, six ignored (OS-keychain
integration tests requiring real backend interaction). New
coverage:

  - provcheck-sign:
    * sign_action_round_trips_string — SignAction::parse parses
      both short and canonical forms; bogus inputs return None.
    * inspect_source_returns_none_for_unsigned_file.
    * inspect_source_returns_signer_for_signed_file.
    * default_action_routes_on_provenance — verifies
      None → Created and Some → Published.
    * republish_chains_parent_ingredient — round-trips a two-cert
      flow (cert A signs, cert B re-signs); asserts the active
      manifest carries a parentOf ingredient with a non-empty
      label pointing into the manifest store.

  - provcheck:
    * publisher_attestation_chain_surfaces_parent_in_report —
      end-to-end producer + verifier round-trip; asserts
      Report.parents has at least one entry with at least one
      identifying field populated.

Wire-format note: no breaks. v0.3.0 binaries continue to verify
v0.3.1-signed files and vice versa.

Tooling change shipped alongside:

  scripts/publish_dc.sh — formalises the release ceremony into one
  command. Reads release-notes/<tag>/{commit,tag}.md and
  release-notes/<tag>/files.txt, stages the listed files, commits,
  pushes main, tags, pushes the tag, watches the release workflow
  to completion, downloads artefacts, and hands off to
  publish-release.sh. Each release prep now produces a
  release-notes/<tag>/ dir with those three inputs; the publisher
  runs the script.
