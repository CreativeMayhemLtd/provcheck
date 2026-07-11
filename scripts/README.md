# scripts/

Maintenance scripts. None are required for building or running
provcheck — they exist for specific operator tasks.

## `make-unsigned-examples.py`

Regenerates the deliberately-unsigned audio + video samples in
`examples/`. Run from the repo root:

```bash
python scripts/make-unsigned-examples.py
```

Requires Python 3.8+ and ffmpeg on `PATH` (or set `$FFMPEG`).
