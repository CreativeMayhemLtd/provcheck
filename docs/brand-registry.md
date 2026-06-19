# Brand registry — numeric IDs for short-payload watermarks

silentcipher's 40-bit payload encodes brands as ASCII triplets
(`DFM` = doomscroll.fm, `RAI` = rAIdio.bot, `VAI` = vAIdeo.bot).
The shorter payloads of AudioSeal (16 bits) and WavMark (32 bits)
don't have room for ASCII. Instead, they use **numeric** IDs from
the registry below.

This document is the single source of truth. The Rust constant
table lives at `crates/provcheck-audioseal/src/registry.rs` and is
re-used by `provcheck-wavmark`.

## The registry

| 16-bit ID | Brand | Display label | ASCII equivalent (silentcipher) |
|---|---|---|---|
| `0x0001` | doomscroll.fm | `doomscroll.fm` | `DFM\x01\x00` |
| `0x0002` | rAIdio.bot | `rAIdio.bot` | `RAI\x01\x00` |
| `0x0003` | vAIdeo.bot | `vAIdeo.bot` | `VAI\x01\x00` |

Reserved ranges:

| Range | Status | Use |
|---|---|---|
| `0x0000` | Reserved | Null / unallocated. Never used as a brand. |
| `0x0001` – `0x00FF` | Allocated | Current Creative Mayhem suite + early third-party. Slots `0x0004`+ available on request. |
| `0x0100` – `0xFFFE` | Reserved | Future registry expansion. New families slot in here once the policy below has more codified governance. |
| `0xFFFF` | Reserved | Sentinel for "no brand" / "all bits 1". Never used as a brand. |

## Encoding into the payload

### AudioSeal (16-bit payload)

The full 16 bits ARE the brand ID, big-endian.

```
payload[0]  payload[1]
+--------+--------+
|  high  |  low   |
|  byte  |  byte  |
+--------+--------+

ID = (high << 8) | low
```

Example: doomscroll.fm marked content has payload bytes `00 01`,
which reads as ID `0x0001`.

### WavMark (32-bit payload)

The lower 16 bits hold the brand ID using the same encoding as
AudioSeal. The upper 16 bits are reserved for per-family metadata —
currently zero. Future versions may use the upper bits for episode
identifiers, timestamps, or schema versioning per family.

```
payload[0..2]      payload[2..4]
+-------+-------+ +-------+-------+
|   reserved    | |   brand ID    |
|   (16 bits)   | |   (16 bits)   |
+-------+-------+ +-------+-------+

ID    = u16::from_be_bytes(payload[2..4])
extra = u16::from_be_bytes(payload[0..2])
```

Until the upper bits are assigned a meaning, parsers should treat
non-zero upper bits as informational only — the brand classification
falls out of the lower 16 bits.

### silentcipher (40-bit payload)

silentcipher does NOT use this registry. It keeps its established
ASCII-triplet + schema-byte convention. The ASCII equivalents in
the table above are documented purely so a reader of a hex dump
can recognise that two formats encode the same brand.

## How a new brand joins the registry

1. **Open a PR** against `docs/brand-registry.md` adding a row to
   the table, plus a constant to
   `crates/provcheck-audioseal/src/registry.rs`. Pick the next
   unused slot in `0x0001` – `0x00FF`.
2. **Update `provcheck::report::WatermarkBrand`** with a new enum
   variant. This is wire-format-touching — bump the workspace
   minor version (`0.X.0`) and call it out in release notes.
3. **Update the parser tests** in `provcheck-audioseal::brand` and
   `provcheck-wavmark::brand`.
4. **Update silentcipher's `BRAND_*` constants in
   `provcheck-watermark::brand`** if the brand also wants a
   silentcipher ASCII triplet, AND register the brand under
   `WATERMARK_LICENSE_POLICY.md`'s policy summary.

There's no central registrar; the PR is the registration. We're
small enough that this works. When the registry gets to two-digit
brand count we can revisit governance.

## What "unknown brand ID" looks like in the report

The verifier reports brands not in the registry as
`WatermarkBrand::UnknownNumeric { id }`. Display label:
`unknown brand (id 0xXXXX)`. The raw payload bytes are still
shown verbatim on the report line for forensics.

If you see an unknown-numeric brand in a verified file, two
possibilities:

1. The registry is out of date — a new brand has joined but
   provcheck hasn't been updated. Check the registry doc on the
   public mirror; bump the binary.
2. Someone is using an ID outside the allocated range. Either a
   typo at encode time, or a deliberately spoofed mark. The
   verifier reports the ID without taking sides on intent.

## Why we chose big-endian and a flat 16-bit ID

- **Big-endian** matches the bytewise reading convention of network
  protocols and human-readable hex dumps. `00 01` reads as "one"
  without mental gymnastics.
- **Flat ID** (vs `family_byte + schema_byte`) keeps the registry
  shape uniform across AudioSeal and WavMark. Schema/version
  evolution can live in the upper bits of WavMark's 32-bit payload
  later if we need it.
- We considered ASCII for the lower 8 bits + schema for the upper
  8 bits, but that would have made the registry look like a hybrid
  of silentcipher's convention. Keeping the formats distinct
  signals "different encoding family" to a reader of the spec.
