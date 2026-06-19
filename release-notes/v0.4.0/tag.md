v0.4.0: AudioSeal detect + embed

Second neural-watermark family lands. Verifier reports AudioSeal
hits alongside silentcipher; `kit watermark --kind audioseal`
embeds an AudioSeal mark with 5-bit brand ID + 3-copy ECC.

End-to-end on a 60 s sample: embed 21.9 s, detect 2.6 s, SDR 44 dB,
brand recovered correctly even when AudioSeal's ~6 % per-bit error
flips one bit.

New: shared numeric brand registry (`docs/brand-registry.md`),
`marked_regions` optional time-span field on `WatermarkResult`,
`UnknownNumeric` variant on `WatermarkBrand`.

WavMark is the same shape but parameters; ships as v0.4.1.
