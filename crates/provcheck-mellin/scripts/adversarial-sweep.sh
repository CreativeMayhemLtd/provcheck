#!/usr/bin/env bash
# Audio-domain adversarial sweep for the provcheck-mellin channel.
#
# Embeds a known serial, applies each attack with ffmpeg, and reads it back,
# printing a survival table. Audio-domain signal
# processing is the real adversary for an audio watermark; the image/text/metadata
# provenance strippers cannot engage it.
#
# Requires: the release binary (cargo build --manifest-path Cargo.toml --release),
# ffmpeg on PATH (or $FFMPEG), python3 with numpy for the synthetic base.
#
# Usage: bash scripts/adversarial-sweep.sh [workdir]
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${MELLIN_BIN:-$HERE/target/release/provcheck-mellin}"
[ -x "$BIN" ] || BIN="$BIN.exe"
FF="${FFMPEG:-ffmpeg}"
SECRET=00112233445566778899aabbccddeeff
WID=sweep-work
SER=cafe1234
REPEAT="${REPEAT:-8}"
STR="${STRENGTH:-0.35}"
D="${1:-$(mktemp -d)}"
mkdir -p "$D"; cd "$D" || exit 1

python3 -c "
import numpy as np, wave
sr=44100; N=sr*60; rng=np.random.default_rng(21); t=np.arange(N)/sr
x=np.clip(rng.standard_normal(N)*0.15+0.2*np.sin(2*np.pi*220*t)+0.12*np.sin(2*np.pi*523*t)+0.08*np.sin(2*np.pi*1100*t),-1,1)
w=wave.open('base.wav','w'); w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr); w.writeframes((x*30000).astype('<i2').tobytes()); w.close()
"
"$BIN" embed --secret $SECRET --work-id $WID --serial $SER --repeat "$REPEAT" --strength "$STR" base.wav -o marked.wav >/dev/null 2>&1

read_one () { # label file
  local out bits votes verdict
  out=$("$BIN" read --secret $SECRET --work-id $WID --repeat "$REPEAT" --strength "$STR" --expect $SER "$2" 2>/dev/null)
  bits=$(echo "$out" | grep -oE 'bits recovered:  [0-9]+' | grep -oE '[0-9]+$')
  votes=$(echo "$out" | grep -oE 'min bit votes:   [0-9]+' | grep -oE '[0-9]+$')
  if echo "$out" | grep -q '^MATCH'; then verdict="SURVIVES"
  elif [ "${bits:-0}" -ge 58 ]; then verdict="DEGRADED"; else verdict="FAIL"; fi
  printf '| %-26s | %-8s | %s/64 | %s |\n' "$1" "$verdict" "${bits:-0}" "${votes:-0}"
}
atk () { # label ext ffmpeg-args...
  local label="$1" ext="$2"; shift 2
  "$FF" -y -loglevel error -i marked.wav "$@" "out_${label}.${ext}" 2>/dev/null
  [ -f "out_${label}.${ext}" ] && read_one "$label" "out_${label}.${ext}" \
    || printf '| %-26s | ENCFAIL |  |  |\n' "$label"
}

echo "| Attack | Verdict | Bits | MinVotes |"
echo "|---|---|---|---|"
read_one "clean WAV (control)" marked.wav
atk "MP3 320k"    mp3  -c:a libmp3lame -b:a 320k
atk "MP3 192k"    mp3  -c:a libmp3lame -b:a 192k
atk "MP3 128k"    mp3  -c:a libmp3lame -b:a 128k
atk "MP3 96k"     mp3  -c:a libmp3lame -b:a 96k
atk "AAC 128k"    m4a  -c:a aac -b:a 128k
atk "AAC 96k"     m4a  -c:a aac -b:a 96k
atk "Opus 128k"   opus -c:a libopus -b:a 128k
atk "Opus 96k"    opus -c:a libopus -b:a 96k
atk "FLAC lossless" flac -c:a flac
atk "atempo +5% (WSOLA)"   wav -af atempo=1.05
atk "atempo -5% (WSOLA)"   wav -af atempo=0.95
atk "atempo +10% (WSOLA)"  wav -af atempo=1.10
atk "resample +3% (speed)" wav -af asetrate=45423,aresample=44100
atk "resample -3% (speed)" wav -af asetrate=42777,aresample=44100
atk "resample +6% (speed)" wav -af asetrate=46746,aresample=44100
atk "low-pass 6 kHz"       wav -af lowpass=f=6000
atk "low-pass 4 kHz"       wav -af lowpass=f=4000
atk "volume -6 dB"         wav -af volume=-6dB
atk "volume +6 dB"         wav -af volume=6dB
atk "loudnorm"             wav -af loudnorm
atk "trim 5s..55s (crop)"  wav -ss 5 -t 50
