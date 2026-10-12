# provcheck-app GUI messages, English (source of truth). Only complete user-facing
# sentences returned to the GUI as ApiResult ok/err text are localized here; technical
# { $err }/log-path diagnostics and IPC error labels stay English. Brand and technical
# literals (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, file names) stay verbatim in every locale.

## Backfire keyed-image tab (backfire_read + install_backfire).
backfire-read-needs-key = A key is required to read a Backfire mark.
backfire-folder-unresolved = Could not resolve a writable Backfire folder (LOCALAPPDATA unset).
backfire-ready-bundled = Backfire is ready (bundled reader present). Enter a key and drop an image.
backfire-files-missing = Backfire files not found to install. Reinstall provcheck, or set BACKFIRE_PY.
backfire-ready = Backfire is ready. Enter a key and drop an image.

## Mellin keyed-marks tab (mellin_read).
mellin-needs-secret-and-work-id = A secret file and a work id are required to read a Mellin serial.
mellin-secret-file-missing = The chosen secret file does not exist (or is not readable).

## Sign + Keys tabs: GUI capability-limit notices returned as ApiResult errors.
identity-already-exists = an identity already exists at this data directory; pass force=true to regenerate (this orphans any previously-published atproto records)
rotate-yubikey-unsupported = GUI rotation of a Yubikey-backed identity isn't supported yet. Run `provcheck-kit init --yubikey --force` from a terminal, then come back here to publish + revoke.
rotate-agefile-unsupported = GUI rotation of age-file-backed identities isn't wired yet. Use `provcheck-kit rotate` from a terminal.
sign-keychain-only = GUI signing currently supports OS-keychain identities only. Use `provcheck-kit sign` from the CLI for age-file identities.
sign-yubikey-unsupported = GUI signing of Yubikey-backed identities lands in v0.5.0 P3 + P4. For now, sign via `provcheck-kit sign` from a terminal — the kit prompts for the PIV PIN on each signature.
