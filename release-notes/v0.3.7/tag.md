v0.3.7: chunked watermark inference — fix OOM on multi-minute MP3s

Closes a doomscroll.fm-reported OOM where verifying a 211-second
MP3 ate ~11 GB RSS before the Linux kernel killed the process. The
watermark detector now feeds tract in fixed 256-frame chunks
instead of the whole carrier at once, capping peak memory at ~1.5
GB regardless of audio length. Logits, payloads, and confidence
all match the v0.3.6 output on the reference fixtures to within
f32 round-off.

No wire-format changes.
