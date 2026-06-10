# Watermark Detector License Policy

provcheck is licensed Apache-2.0 and we keep it that way. Anything bundled into
the binary — code, model weights, configuration — has to be license-compatible.
This document is the durable rule, not just a one-time judgement call.

## The rule

A watermark detector can ship inside provcheck **only if both its code and its
trained model weights are released under one of**:

- MIT
- Apache-2.0
- BSD-2-Clause / BSD-3-Clause
- ISC
- CC0 / public domain
- Anything else that the OSI lists as approved AND that does not encumber
  redistribution, commercial use, or derivative works

If the model weights ship under a separate license from the code, **both** must
pass. A repo with MIT code and CC-BY-NC weights fails. A repo with MIT code and
a community-license-only model fails. A repo with no published weights at all
fails (we have nothing to detect against).

We explicitly **reject**:

- CC-BY-NC, CC-BY-ND, CC-BY-NC-SA, and any other non-commercial Creative
  Commons variants
- "Research-only" or "non-commercial use only" custom licenses
- "Community licenses" with acceptable-use riders (Llama Community License,
  Gemma terms, OpenRAIL-M with use restrictions, etc.) — well-intentioned, but
  they don't compose with Apache-2.0
- Anything requiring opt-in registration, account creation, or terms acceptance
  to obtain the weights
- Anything proprietary / closed (private model, gated API, etc.)

A detector that fails the test is still useful to *describe* — provcheck can
document that the format exists and link to the upstream tool — but we will not
add a Rust crate or sibling detector that depends on it.

## Why

Three reasons, in priority order:

1. **License hygiene.** Apache-2.0 is permissive; pulling in a restrictively-
   licensed model means provcheck's own license claim becomes false. Users who
   bundle provcheck into a commercial pipeline have to either pull the
   restricted detector out, or relicense everything around it. Both are
   user-hostile.
2. **Distribution simplicity.** The release binary is one self-contained
   `.exe`. Mixing licenses inside that artefact creates a compliance burden
   (LICENSE-of-LICENSEs files, mandatory attribution layers, redistribution
   carve-outs) every time someone re-hosts it. The free-software default is
   "you can re-host this." We protect that default.
3. **Symmetry with what we ship.** rAIdio.bot, doomscroll.fm, and the rest of
   the Creative Mayhem suite are open. The verifier should be too. A detector
   we'd refuse to sign off on for the artist-side tools doesn't belong on the
   verifier either.

## Watermark families surveyed (2026-06-09)

| Family | Maintainer | Code license | Weights license | Pass? | provcheck status |
| --- | --- | --- | --- | --- | --- |
| **silentcipher** | Sony AI | MIT | MIT | ✓ | **Integrated** in `provcheck-watermark` — full STFT + tract pipeline. Detection live. |
| **AudioSeal** | Meta (FAIR) | MIT | MIT (since 2024-04-02) | ✓ | **Scaffolded** in `provcheck-audioseal` — crate exists, wired into CLI/GUI dispatch, returns `implementation pending` until the decoder is ported. Pre-relicense (CC-BY-NC) era would have been rejected. |
| **WavMark** | independent (paper 2308.12770) | MIT | MIT (weights ship via PyPI `wavmark`) | ✓ | **Scaffolded** in `provcheck-wavmark` — same scaffold pattern as AudioSeal. |
| **SynthID Audio** | Google DeepMind | unreleased | unreleased | ✗ | **Not added.** Detection only via Gemini / SynthID Detector portal (early-tester waitlist). No public model, no public API. Re-survey if Google open-sources it. |
| classical echo-hiding / LSB / spread-spectrum | — | — | — | ✓ | **Not added.** Algorithmic, no model weights; would be implemented in pure Rust from the relevant papers. No upstream license to inherit. |

All three FOSS-eligible neural families now have a Rust home. silentcipher
runs a full pipeline; AudioSeal and WavMark are scaffold-only — each crate's
`lib.rs` carries its own license-verification narrative, integration
checklist, and `implementation pending` stub `detect()`. SynthID stays out
on license grounds (effectively, it has no license — the detector isn't
public). The classical-algorithm row is forever-eligible but unstaffed.

## Process for adding a new detector

1. Confirm the family passes the rule above. If license terms have changed
   since this document was last touched, update the table.
2. Create a sibling crate `crates/provcheck-<family>/` mirroring the structure
   of `crates/provcheck-watermark/`. Detector implementation, embedded weights,
   public `detect(path) -> Result<WatermarkResult, Error>` API.
3. Add a `WatermarkKind` variant in `crates/provcheck/src/report.rs` for the
   new family.
4. In `crates/provcheck-cli/src/main.rs` and `app/src-tauri/src/main.rs`,
   append another `if let Ok(w) = provcheck_<family>::detect(&path) { ... }`
   block in the detector dispatch. The vec layout means no other plumbing
   changes are needed — CLI Display, GUI rendering, and JSON serialization
   all iterate `report.watermarks` already.
5. Re-verify the clean-Windows-sandbox release gate (see
   `.cargo/config.toml` + the project memory).

## Re-survey trigger

Re-check the table any time one of the maintainers makes a license
announcement, or annually as a hygiene pass. The 2024-04-02 AudioSeal
relicensing from CC-BY-NC to MIT is the canonical "why we re-survey" example.
