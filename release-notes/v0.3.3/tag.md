v0.3.3: silentcipher detector — honor MP3 encoder delay

Audio decode now trims the LAME priming + end-padding samples that
symphonia parses but does not auto-strip. Closes the detection
confidence gap on LAME-encoded MP3 input: on a known-marked file,
v0.3.2 reported 0.49 confidence with the wrong payload and
classifier-rejected as not_detected; v0.3.3 reports 0.83 with the
correct payload, matching the Python reference to f32 round-off.

Also: stft.rs aligns periodic Hann + always-pad invariants to
silentcipher's training reference, and the v0.3.2 diagnostic
harness (decode_dump / decode_diff / align_check + Python
reference + docs) ships in-repo as the regression suite.

No wire-format breaks.
