# Example signed media

Two files here to kick the tires with. Both carry real C2PA Content
Credentials and verify cleanly under `provcheck`.

## `rAIdio.bot-sample.mp3` (+ `rAIdio.bot-sample.c2pa` sidecar)

~2 MB AI-generated music (808 trap tune) produced by
[**rAIdio.bot**](https://store.steampowered.com/app/4600000), a
local-first AI music generation studio from
[Creative Mayhem UG](https://creativemayhem.app).

Signed with a C2PA manifest that includes:

- `c2pa.actions.v2` — marks the file as AI-generated
  (`digitalSourceType = trainedAlgorithmicMedia`, per IPTC).
- `com.raidio.model` — the model used (ACE-Step 1.5 XL, Apache-2.0,
  "No copyrighted music in training set").
- `com.raidio.product` — product name, vendor, URL.

MP3 format carries its manifest as an **external `.c2pa` sidecar** —
`rAIdio.bot-sample.c2pa`. Keep it next to the MP3; `provcheck` picks
it up automatically.

```
provcheck examples/rAIdio.bot-sample.mp3
```

## `doomscroll.fm-sample.mp4`

~660 KB short AI-generated video bumper from
[**Doomscroll.fm**](https://doomscroll.fm) — an autonomous AI
satirical news broadcast by [Creative Mayhem UG](https://creativemayhem.app),
producing ~10–12 episodes per day, all signed at source.

Signed with a C2PA manifest that includes:

- `c2pa.actions.v2` — AI-generated marker.
- `c2pa.hash.bmff.v3` — data-hash binding for the MP4 payload, so
  tampering with the video bytes invalidates verification.
- `com.doomscroll.broadcast` — broadcast attribution + vendor.
- `com.doomscroll.distribution` — **template pattern** for any C2PA
  publisher whose content might be rebroadcast through platforms
  that re-encode media on upload. Contains four fields:
  - `provenanceStatement` — states plainly what a C2PA signature
    does and doesn't mean. The signature attests that the bytes
    are authentic to what the publisher published; it is a
    provenance claim, not a truth claim about the content.
  - `canonicalSource` — the URL where the authoritative signed
    publication lives.
  - `canonicalSourceDescription` — reinforces that this is where
    the always-signed copy lives.
  - `rebroadcastDisclaimer` — tells end users that a file failing
    verification is not necessarily altered; it may just have lost
    its signature during re-encoding at a redistribution platform.
    Directs them to the canonical source to verify the original.
  - `integrityRecommendation` — tells republishers and archivists
    to pull from the canonical source to keep the signature chain
    intact.

  Worth shipping in any publisher's manifest. End users who
  encounter stripped copies online get a clear path to re-verify
  against the authoritative publication instead of having to guess
  what signature loss means.
- `com.doomscroll.episode` — episode-level context.

MP4 format carries its manifest **embedded in the file** — no
sidecar.

```
provcheck examples/doomscroll.fm-sample.mp4
```

## Regenerating

Both samples are produced deterministically from the upstream source
files by the in-tree `provcheck-examples` binary:

```
cargo run --release -p provcheck-examples -- \
  --audio-in <path-to-rAIdio-mp3> \
  --video-in <path-to-Doomscroll.fm-bumper-mp4> \
  --out-dir examples
```

Each run synthesises a fresh ES256 cert chain (the common-name on
the signing cert is the brand — rAIdio.bot or Doomscroll.fm — which
is what `provcheck` surfaces as `signer`). No private keys ship with
this repo.

## Licensing

The audio + video content in these samples is AI-generated output
from Creative Mayhem UG products. These specific sample files are
licensed under Apache-2.0 along with the rest of this repository.

Training data for the underlying AI models (where applicable) is
disclosed in the embedded manifests — read them via `provcheck` and
look at `com.raidio.model.trainingDataSource` and
`com.raidio.model.trainingDataLicense`.
