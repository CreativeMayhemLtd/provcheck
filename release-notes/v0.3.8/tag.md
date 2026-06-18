v0.3.8: silentcipher watermark EMBEDDING

Closes the doomscroll.fm-reported production block where ffmpeg
loudness normalisation destroyed render-time silentcipher marks.

New: `provcheck-kit watermark <input> -o <output.wav>` re-stamps
the mark into the post-normalisation audio. End-to-end verified
at 88% confidence on a 60-second real audio fixture, with embed
wall-clock at 0.82x real-time and peak RSS capped at ~1.5 GB
regardless of audio length.

silentcipher encoder ONNX (Sony Research, MIT) ships embedded in
the binary alongside the existing decoder ONNX. Two small pieces
(linear projection + utterance normalisation scalar) stay in Rust
to work around tract 0.21 limitations and the chunking design.

No wire-format changes on the verifier side.
