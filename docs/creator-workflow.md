# Creator workflow — sign + publish + cross-verify

End-to-end guide for using `provcheck-kit` to sign your media with a
C2PA manifest and bind your atproto identity to the signature. Targets
a creator who's never used the tool before; assumes you already have
a bluesky / atproto handle.

If you only want to *verify* files (not sign them), use `provcheck` —
this guide is for the producer side.

## What you need before you start

- An atproto handle (e.g. `you.bsky.social`) and an app password.
  Generate one at [bsky.app → Settings → App Passwords](https://bsky.app/settings/app-passwords).
- The `provcheck-kit` binary. Either download from the
  [Releases page](https://github.com/CreativeMayhemLtd/provcheck/releases)
  or `cargo install --path crates/provcheck-kit` from a source clone.
- About five minutes for first-time setup.

## 1. Mint your identity

```bash
provcheck-kit init
```

This mints a fresh ES256 signing keypair, generates a self-signed
certificate chain, and stashes everything in your data directory:

- Linux/macOS: `$XDG_DATA_HOME/provcheck-kit/` (default `~/.local/share/provcheck-kit/`)
- Windows: `%APPDATA%\provcheck-kit\`

Public material (cert chain, fingerprint metadata) goes to a `keys/`
subdirectory in plain files. The **private key** goes to your OS
keychain by default:

- macOS — Keychain Services, service `app.provcheck.kit`
- Windows — Credential Manager, target `app.provcheck.kit:<fingerprint>`
- Linux — Secret Service (gnome-keyring / kwallet / libsecret)

On headless boxes (CI, Docker, servers with no keychain daemon), pass
`--age-file` to use an age-encrypted file with a passphrase you choose:

```bash
provcheck-kit init --age-file
```

You can register one or more X25519 recovery recipients up front for
break-glass restore — see `provcheck-kit init --help`.

## 2. Attach your atproto identity

```bash
provcheck-kit login -u you.bsky.social
```

This prompts for your app password (input is hidden). On success, the
kit stores a session token under your data directory (`session.json`).
Tokens refresh automatically as you use other commands; once the
refresh token itself expires (~2 months), you'll need to re-run
`login`.

## 3. Publish your signing-cert fingerprint

```bash
provcheck-kit publish
```

This writes an `app.provcheck.signingKey` record to your atproto
account containing the SHA-256 fingerprint of your signing cert plus
metadata (algorithm, label, optional valid-from / valid-until).
Anyone running `provcheck` against a file you sign can then ask
atproto "did this DID publish this fingerprint?" and get a verifiable
answer.

The record format is fully specified in
[`docs/atproto-signing-key.md`](./atproto-signing-key.md).

## 4. Sign a file

```bash
provcheck-kit sign mix.wav --embed-identity
```

This signs `mix.wav` in place via a temp-file + atomic-rename dance.
The resulting file:

- carries a C2PA manifest with your cert chain,
- declares a `c2pa.actions.v2` assertion (default action `created`),
- carries an `app.provcheck.identity` assertion with your DID baked in
  (because of `--embed-identity`) — this lets verifiers auto-fill the
  identity-check without the recipient having to type your handle.

`--action` lets you override the C2PA action label:

| Action | When to use |
|---|---|
| `created` | This is fresh content you produced — the default. |
| `edited` | You modified an existing C2PA-signed file. |
| `opened` | You loaded and re-saved without meaningful edits. |
| `published` | You're a publisher re-attesting someone else's upstream-signed content. The kit auto-chains your signature on top as a derivative, preserving the original creator's provenance. This is the default when the input already has a C2PA manifest. |

Pass `--manifest <path-to-json>` to drive the manifest fully yourself
instead of accepting the kit's default.

## 5. Recipient verifies + cross-checks

The recipient runs:

```bash
provcheck mix.wav --auto-identity
```

Reports:

- **VERIFIED** — the C2PA signature cryptographically checks out.
- **signer: you** — pulled from the certificate's common name.
- **attested by @you.bsky.social** — proof that your atproto identity
  published this exact cert fingerprint. This is the line that says
  "the signer on the file really is the person behind the handle on
  the file."

Recipients without `--auto-identity` can pass `--bsky-handle
you.bsky.social` or `--did did:plc:...` explicitly — same cross-check
mechanism, just typed by hand.

Stricter modes:

- `--require-attested` makes the cross-check a hard gate (exit 1 if
  it fails).
- `--require-trusted --trust-store <bundle.pem>` makes the cert-chain
  trust a hard gate.
- `--require-watermark` requires a recognised neural watermark on top
  (silentcipher).

## Lifecycle commands

```bash
provcheck-kit list           # show every signing-key record under your DID,
                             # active + revoked + superseded
provcheck-kit status         # local: fingerprint, backend, session state,
                             # published-record summary
provcheck-kit revoke <fp>    # stamp validUntil=now on a record (audit-preserving)
provcheck-kit rotate         # mint a fresh key, publish it, revoke the old
                             # one with supersededBy linkage, atomic
```

`rotate` auto-backs the old identity up to a sibling age file before
the swap — so you can still decrypt material you signed under the old
key, but the old fingerprint is no longer attested in atproto.

## Backup + restore

```bash
provcheck-kit export-backup ~/safe.age         # passphrase-encrypted
provcheck-kit export-backup ~/safe.age \
    --use-recovery-recipients                  # X25519-encrypted to registered recipients
provcheck-kit import-backup ~/safe.age         # restore on a different machine
```

For passphrase backups: prompts twice with confirm. For
recovery-recipient backups: encrypts to the set you registered with
`add-recovery-recipient` (a Yubikey-held age identity, a colleague's
pubkey, a printed offline pubkey in a safe). Anyone holding a matching
private key can decrypt.

**Recovery-recipient revocation has a known footgun.** Removing a
recipient affects only *future* backups; every backup file already
written stays decryptable by them forever (age has no retroactive-
revocation primitive). The only mechanism that actually cuts their
signing power is `kit rotate` — fresh fingerprint published, old
fingerprint revoked via atproto, so even if they can decrypt the old
age file, the old fingerprint isn't attested anymore. See
`provcheck-kit remove-recovery-recipient --help` for the full warning
text.

## Integration patterns

### Render pipeline / Docker

Pull the Linux binary into your container:

```dockerfile
FROM debian:bookworm-slim
ARG PROVCHECK_VERSION=v0.6.0
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -L \
    "https://github.com/CreativeMayhemLtd/provcheck/releases/download/${PROVCHECK_VERSION}/provcheck-kit-${PROVCHECK_VERSION}-linux-x86_64.tar.gz" \
  | tar -xzf - --strip-components=1 -C /usr/local/bin/
```

At render time, after writing the output file:

```bash
provcheck-kit sign /path/to/output.wav --embed-identity --action created
```

For batch operation in a long-running process, `provcheck-kit unlock`
once at startup primes the in-process passphrase cache (encrypted-file
backend only — the OS keychain handles batching natively via
"always allow").

### Batch watermark embedding (v0.6.0)

For pipelines that watermark many files in a row, `kit serve`
amortises the silentcipher model load across all requests in a
single worker session. Cold-start tract optimisation runs once
(~3 seconds), not once per file.

```bash
# Request shape (one JSON object per line on stdin):
#   {"id": "ep001", "input": "ep001.mp3", "output": "ep001.wav",
#    "kind": "silentcipher", "payload": "44464d0100",
#    "sdr_db": 30.0, "memory_budget": "default",
#    "verify_after_embed": true, "overwrite": true, "channels": "auto"}
provcheck-kit serve <requests.jsonl >responses.jsonl
```

Memory budget knobs for the watermark subcommand:

- `--memory-budget default` — chunk-parallel rayon up to 4-wide.
  Best wall clock. Peak RSS ~11 GB on a 56-min stereo episode.
- `--memory-budget low` — sequential chunks. Trades wall clock
  for memory. Peak RSS ~5 GB on a 56-min stereo episode.
- `--memory-budget streaming` — chunk-fused streaming embed.
  Never materialises the full spectrogram. Same memory profile
  as `low` but ~25% faster wall clock; the better choice for
  most memory-constrained hosts.

### GPU acceleration (v0.6.0, CUDA, opt-in build)

For shops with NVIDIA hardware on the render host, the
`--features cuda` build routes the silentcipher embed encoder
through `ort` 2.x's CUDA Execution Provider. A 56-min stereo
episode embed drops from 29 minutes (4-wide CPU) to about 6.6
minutes on an NVIDIA 3090.

The default download stays a single tract-only CPU binary. The
CUDA build is opt-in:

```bash
# Build from source on the render host:
git clone https://github.com/CreativeMayhemLtd/provcheck
cd provcheck
CARGO_TARGET_DIR=./target-cuda cargo build --release --features cuda --bin provcheck-kit

# At runtime, point the kit at onnxruntime-gpu's shared libraries.
# On Windows after `pip install --user onnxruntime-gpu`:
set ORT_DYLIB_PATH=%APPDATA%\Python\Python312\site-packages\onnxruntime\capi\onnxruntime.dll
set PATH=%PATH%;C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8\bin

./target-cuda/release/provcheck-kit watermark episode.mp3 -o episode.wav
```

NVIDIA libraries are not redistributed in our release archives
per their license terms; install them separately on the host.
Full design notes at [`docs/v0.6.0-roadmap/`](../docs/v0.6.0-roadmap/).

### CI verification gate

```bash
provcheck --quiet --require-trusted --trust-store roots.pem rendered.wav
if [[ $? -ne 0 ]]; then
    echo "rendered file failed C2PA verification — aborting publish"
    exit 1
fi
```

## When something goes wrong

- **Publish fails with `recordAlreadyExists`** — you already have a
  signing-key record for this fingerprint. Add `--force` to overwrite,
  or check `provcheck-kit list` first.
- **Sign fails with `not a recognised audio container`** — the input
  file's format isn't supported by c2pa-rs. See the supported-formats
  list in the [main README](../README.md).
- **`provcheck --auto-identity` reports "no identity assertion"** —
  the file wasn't signed with `--embed-identity`. Use `--bsky-handle`
  or `--did` instead.
- **Verifier reports VERIFIED but attestation `unknown`** — the
  recipient ran without `--bsky-handle` / `--did` / `--auto-identity`.
  Cryptographic signature is valid; identity cross-check wasn't
  attempted. Re-run with one of those flags to get an attestation
  verdict.
- **Backup decryption asks for a passphrase you forgot** — if you
  registered any X25519 recovery recipients before the backup, any of
  them can unwrap it. If you didn't, the data is unrecoverable —
  age's authenticated-encryption is genuine; there is no backdoor.

## See also

- [`docs/atproto-signing-key.md`](./atproto-signing-key.md) — full
  wire-format spec for the `app.provcheck.signingKey` record and the
  `app.provcheck.identity` C2PA assertion.
- [`README.md`](../README.md) — verifier-side documentation,
  install options, exit codes.
- [`provcheck-kit --help`](https://github.com/CreativeMayhemLtd/provcheck/blob/main/crates/provcheck-kit/src/main.rs)
  — the canonical command reference, always up-to-date with the
  binary you have installed.
