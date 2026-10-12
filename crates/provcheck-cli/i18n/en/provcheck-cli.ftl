# provcheck-cli runtime output, English (source of truth). Human-readable output only;
# --json output and exit codes are never localized. Placeholders { $name } are filled at
# call sites; keep them intact in translations. Brand and technical literals (provcheck,
# C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags, file names) stay
# verbatim in every locale.

## Mellin keyed-audio forensic block (print_mellin_human).
mellin-header = Mellin (experimental, keyed audio forensic serial):
mellin-serial-full = serial:   { $serial } (all 64 bits recovered, min bit votes { $votes })
mellin-serial-partial = serial:   not fully recovered ({ $bits }/64 bits, min bit votes { $votes })
mellin-erasures = erasures: { $pct }% of positions
mellin-expected-match = expected: MATCH
mellin-expected-no-match = expected: NO MATCH

## Backfire keyed-image watermark block (print_backfire_human).
backfire-header = Backfire (experimental, keyed image watermark):
backfire-mark-valid = mark:   VALID (id { $id }, margin { $margin })
backfire-mark-none = mark:   not detected (margin { $margin })
backfire-tamper-detected = tamper: BAND-NOTCH DETECTED (stat { $stat }) -- the image was very likely notch-attacked
backfire-tamper-none = tamper: none (band-notch stat { $stat })

## Backfire setup (--install-backfire).
backfire-folder-not-found = provcheck: could not locate the backfire folder. Set BACKFIRE_PY to backfire.py, or run from a directory containing backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 not found in { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh not found in { $dir }
backfire-setup-start = Setting up the Backfire read environment (one-time). This downloads a self-contained Python.
backfire-setup-ready = Backfire is ready. Verify a marked image with:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire setup exited with status { $status }
backfire-setup-run-failed = provcheck: could not run the Backfire setup script ({ $err }). It needs PowerShell on Windows, or bash on Linux/macOS.

## Model install (--install-models).
install-models-start = Installing { $count } watermark-detection model file(s) ({ $mb } MB total).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = FAILED: { $err }
install-models-done = All models installed. Watermark detection is ready.
install-models-summary-failed = provcheck: { $count } model(s) failed to install (see above).

## Main verify path: errors, notices, and hints.
require-attested-needs-identity = provcheck: --require-attested needs --bsky-handle, --did, or --auto-identity
trust-store-read-failed = provcheck: could not read trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity was requested but the file carries no app.provcheck.identity assertion. Sign with `provcheck-kit sign --embed-identity` first, or pass --bsky-handle / --did directly.
backfire-needs-key = provcheck: --backfire-read needs --backfire-key
backfire-experimental-notice = provcheck: Backfire is EXPERIMENTAL and BUSL-licensed (free for non-commercial use), separate from the Apache-2.0 core. It verifies a keyed mark you embedded and flags band-notch tampering; robustness is per-image.
backfire-read-failed = provcheck: backfire read failed: { $err }
mellin-needs-args = provcheck: --mellin-read needs --mellin-secret-file and --mellin-work-id
mellin-experimental-notice = provcheck: Mellin is EXPERIMENTAL and BUSL-licensed (free for non-commercial use), separate from the Apache-2.0 core. It reads a keyed per-copy serial you embedded; without your secret and work id there is nothing to read.
mellin-read-failed = provcheck: mellin read failed: { $err }
json-serialize-failed = provcheck: failed to serialize JSON: { $err }
hint-models-missing = [hint] { $count } watermark-detection model(s) are not installed, so those lines read "not installed". Enable all detection with:  provcheck --install-models  (one-time, { $mb } MB). C2PA verification does not need them.
hint-claims-identity = [hint] file claims identity { $who }. Re-run with --auto-identity to verify against their published signing-key records.
