# Example media

Sample files to kick the tires with. The C2PA set below is four files, two
cryptographically verified and two deliberately unsigned; all four are used by
`provcheck-core`'s integration suite so accidental corruption fails CI before you
see it. A separate watermark-detection set (further down) exercises the blind
detectors, and keyed-mark samples live under
[`keyed-samples/`](./keyed-samples/).

## `rAIdio.bot-sample.mp3` (+ `rAIdio.bot-sample.c2pa` sidecar)

~2 MB AI-generated music (808 trap tune) produced by
[**rAIdio.bot**](https://store.steampowered.com/app/4600000), a
local-first AI music generation studio from
[Creative Mayhem UG](https://creativemayhem.com).

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
[**Doomscroll.FM**](https://doomscroll.fm) — an autonomous AI
satirical news broadcast by [Creative Mayhem UG](https://creativemayhem.com),
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

## `unsigned-sample.mp3` and `unsigned-sample.mp4`

33 KB and 46 KB respectively. Both are **deliberately unsigned** —
they exist to demonstrate the UNSIGNED verdict without you having
to hunt for a random file that happens to have no C2PA manifest.

Content: a 2-second 440 Hz sine tone at low amplitude (fade-in and
fade-out to avoid clicks). The MP4 adds a muted dark-blue background
with a subtle hue-pulse and the text "unsigned example" in the
middle. Gentle on the ears, gentle on the eyes.

```
provcheck examples/unsigned-sample.mp3
provcheck examples/unsigned-sample.mp4
```

Both report `[UNSIGNED]` and exit 1. That's the shape every file
without C2PA credentials takes, from any source.

## Watermark detection samples

Beyond C2PA signatures, `provcheck` runs blind watermark detectors on a file and reports
them in the `watermarks` section of the verdict. The pairs below exercise those detectors:
each marked file reports a detection, each unmarked control reports none. Run `provcheck <file>`.

Video detection shells out to `ffmpeg`, so verifying the video sample needs `ffmpeg` on your
PATH (`provcheck` prints a one-line install hint if it is missing).

These sample media files, and the keyed-mark samples under [`keyed-samples/`](./keyed-samples/),
are served on demand: they are bundled with the app installer or downloaded on first use rather
than committed to this repository, which keeps the clone lean. The small C2PA fixtures above stay
in-tree because the integration suite reads them. Re-mark any of them locally with provcheck's own
tooling (TrustMark, SilentCipher, Backfire, Mellin) if you want to regenerate a pair by hand.

### `trustmark-marked.png` (+ `trustmark-unmarked.png`)

A TrustMark-B image watermark (Adobe / CAI, MIT). The marked image reports `trust_mark`
detected (confidence ~7.9); the unmarked control reports not detected.

### `silentcipher-marked.wav` (+ `silentcipher-unmarked.wav`)

A SilentCipher neural audio watermark (MIT). The marked clip reports `silent_cipher`
detected; the unmarked control reports not detected.

### `trustmark-video-marked.mp4` (+ `trustmark-video-unmarked.mp4`)

TrustMark-B written into every frame, read back per-frame with a temporal vote
(`trust_mark_video`, confidence ~11.5). The unmarked control reports not detected. Needs
`ffmpeg` on PATH.

The source media for these samples is derived from public-domain and CC0 content; the marks
are applied by provcheck's own tooling. Keyed marks (Backfire, Mellin) live under
[`keyed-samples/`](./keyed-samples/) with their own README.

## Regenerating

Both samples are produced deterministically from the upstream source
files by the in-tree `provcheck-examples` binary:

```
cargo run --release -p provcheck-examples -- \
  --audio-in <path-to-rAIdio-mp3> \
  --video-in <path-to-Doomscroll.FM-bumper-mp4> \
  --out-dir examples
```

Each run synthesises a fresh ES256 cert chain (the common-name on
the signing cert is the brand — rAIdio.bot or Doomscroll.FM — which
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
