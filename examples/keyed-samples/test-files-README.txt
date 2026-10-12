provcheck sample files (installed with the app)
================================================

These live beside the app so you can try every surface with known-good
inputs. Nothing here ever leaves your machine.

rAIdio.bot-signed-sample.mp3
  Real AI-generated music from rAIdio.bot, C2PA-signed at source.
  Verify tab: expect [VERIFIED], signer info@raidio.bot.

mellin-marked.wav   (experimental keyed mark, audio)
  The same track carrying a keyed Mellin per-copy serial. Read it on the
  Keyed marks tab, Mellin section: choose mellin-secret.txt as the secret
  file, work id = album-x, then choose or drop this file.
  Expect serial 0x000000C0FFEE1234, all 64 bits recovered, match yes.
  CLI:  provcheck.exe --mellin-read --mellin-secret-file mellin-secret.txt --mellin-work-id album-x --mellin-expect 0xC0FFEE1234 mellin-marked.wav
  The app never stores the secret, so re-pick it after every launch.

mellin-unmarked.wav
  The same track without a serial (control). Reads 0 of 64 bits under the
  same secret. Keyed marks never show up in the blind Watermark scan; that
  is the design (no secret, nothing to detect).

mellin-secret.txt
  The demo seller secret for the two files above.

backfire-marked.png   (experimental keyed mark, image)
  A Backfire-marked image. Keyed marks tab, key = backfire-demo-key.
  Expect id 0x7, valid, tamper tripwire clean.
  CLI:  provcheck.exe --backfire-read --backfire-key backfire-demo-key backfire-marked.png

backfire-unmarked.png
  The same photo without a mark (control). No valid mark under any key.

backfire-amplify-demo.png   (Backfire amplification, image)
  A three-panel before/after: original, Backfire-marked, and the marked image after a
  stock diffusion regeneration attack. The keyed read goes from margin 10.8 to 16.3 after
  the attack, stronger than before, with a wrong-key control near zero. Backfire marks are
  visible by design; amplification uses the diffusion-EOT path with your own SD-family
  weights. This is a rendered demo panel, not a readable mark file.

backfire-video-marked.mp4   (Backfire keyed mark, video)
  A short clip carrying the keyed serial on a keyed subset of frames (M2 selective N-frame
  keying). A quorum read recovers id 0x7 through an H.264 re-encode; the unmarked source
  reads nothing. Read it with the backfire video_keying quorum path (video_keying.py in the
  backfire/ directory); a one-command video reader is on the roadmap.
