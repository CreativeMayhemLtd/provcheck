v0.3.9: detector early-exit + parallel chunks + CI fix

Watermark detector now processes chunks in parallel (up to 4 at a
time) and returns early once partial confidence crosses 0.85. On a
60-second marked WAV: 98s → 22s (4.4x speedup), 88% → 92%
confidence — no accuracy regression.

Also fixes the rustdoc trap on encode.rs:246 that turned v0.3.8's
CI red on every platform. (v0.3.8 binaries themselves were and
still are fine; the failure was in the doctest collection step.)

No CLI behaviour or wire-format changes.
