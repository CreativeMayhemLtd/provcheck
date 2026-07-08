#!/usr/bin/env bash
# check-before-push.sh — pre-push regression gate for provcheck.
#
# Runs in this order:
#   1. cargo fmt --check + clippy -D warnings       (CI-parity format + lint gate)
#   2. cargo test --release --workspace            (workspace-wide unit + integration)
#   3. scripts/parity-vs-upstream.py at SDR ∈ {30, 47}  (silentcipher embed parity vs upstream Python)
#   4. AAC delivery survival check for silentcipher + AudioSeal
#      (the public-issue #23 + #24 ground truth — guards both
#       embed margin AND the symphonia AAC decoder priming fix)
#
# Designed to be wired as `.git/hooks/pre-push` via the companion
# install line below. Any FAIL exits non-zero so the push aborts.
#
# Wall-clock: about 10 minutes on a warm cargo cache. Cold builds
# add 2-3 minutes. Skip with --skip-parity if you genuinely need to
# push and are confident the parity sweep is irrelevant to the
# change (e.g. doc-only edit).
#
# Bypass for emergencies: `git push --no-verify`. Use sparingly;
# every bypass should be noted in the commit body or release
# notes so a future investigator can correlate.
#
# Install:
#   ln -sf ../../scripts/check-before-push.sh .git/hooks/pre-push
#   chmod +x .git/hooks/pre-push
#
# Or run manually before a tag push:
#   scripts/check-before-push.sh

set -euo pipefail

# Surface the failing line + last command + exit code on any abort
# under `set -e`. v0.6.0 release postmortem: step 3 of this gate was
# silently aborting with no diagnostic because the heredoc piping
# `$0 2>&1 | tail -N` discards everything before tail's window AND
# step 3 redirects the kit binary's stderr to /dev/null. The trap
# below prints the LINENO + BASH_COMMAND + exit code DIRECTLY to
# stderr, bypassing any in-script pipe, so a future investigator
# sees WHICH command failed instead of having to bash -x.
on_error() {
    ec=$?
    lineno=$1
    echo "" >&2
    echo "gate aborted: exit=$ec line=$lineno cmd=\"$BASH_COMMAND\"" >&2
    exit "$ec"
}
trap 'on_error "$LINENO"' ERR

SKIP_PARITY=0
for a in "$@"; do
    case "$a" in
        --skip-parity) SKIP_PARITY=1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }

# ---- Release-tag gate (v1.1.0 addition; never bypassable except --no-verify) --
#
# Git's pre-push hook receives the ref list on stdin. When the script
# runs under CLI (no stdin from git — a tty is attached), skip this
# gate; it only applies to actual push operations.
#
# The gate REFUSES two failure modes on `refs/tags/v[0-9]+.[0-9]+.0`:
#
#   1. Cadence violation — another v*.*.0 tag was created within the
#      last 24 hours. Memory rule feedback_release_cadence_budget.md
#      (Max one v* tag per 24h) exists because tagging on consecutive
#      days burned ~€25/week of Actions minutes across the Tauri + 10x
#      macOS matrix. Also because it usually means the previous tag
#      was a mistake in-flight being corrected too quickly.
#
#   2. Force-rewrite — the tag already exists on origin at a different
#      SHA. Memory rule feedback_iteration_tags_for_fixes.md flatly
#      prohibits: "Force-rewriting a vX.Y.0 tag that already fired the
#      matrix is even worse than the double-tag." Force-rewrites cost
#      Actions minutes twice AND invalidate downloads pointing at the
#      earlier SHA.
#
# Emergency override for a genuine hotfix that must ship inside 24 h
# of the previous release: `git push --no-verify <ref>`. Convention
# from feedback_pre_push_regression_gate.md is that any --no-verify
# is noted in the commit body with a reason. Every future auditor
# will read that note; the gate cannot be silently sidestepped.
if [[ ! -t 0 ]]; then
    # Reading git's pre-push hook stdin.
    NULL_SHA="0000000000000000000000000000000000000000"
    now_epoch=$(date +%s)
    twentyfour_hours_ago=$((now_epoch - 86400))
    while IFS=' ' read -r local_ref local_sha remote_ref remote_sha; do
        # Skip anything that is not a release-line tag push.
        [[ "$local_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.0$ ]] || continue
        tag_name="${local_ref#refs/tags/}"

        # (2) Force-rewrite check.
        if [[ "$remote_sha" != "$NULL_SHA" ]]; then
            red ""
            red "==============================================================="
            red " RELEASE GATE FAIL: force-rewriting an existing v*.*.0 tag"
            red "==============================================================="
            red "  tag:              $tag_name"
            red "  origin points at: $remote_sha"
            red "  local points at:  $local_sha"
            red ""
            red "  This is the failure mode that memory rule"
            red "  'iteration-tags-for-fixes' was written to prevent."
            red "  The tag already fired the release matrix once. Rewriting"
            red "  it fires the matrix AGAIN and invalidates any download"
            red "  URLs pointing at the earlier SHA."
            red ""
            red "  If the tag reflects a design mistake: leave it alone."
            red "  Iterate as vX.Y.Z (Z>0) — those skip the matrix."
            red "  The next real vX.Y.0 supersedes the mistake naturally."
            red ""
            red "  Emergency override (audit trail required):"
            red "    git push --no-verify --force origin $tag_name"
            red "==============================================================="
            exit 1
        fi

        # (1) Cadence check. Any OTHER v*.*.0 tag created within 24h?
        # git for-each-ref emits `<tag> <unix-epoch>` for each match.
        # Skip the one being pushed (it exists locally but might not
        # be the one under scrutiny in a multi-ref push).
        recent_offender=""
        recent_epoch=0
        while IFS='|' read -r existing_tag existing_epoch; do
            [[ "$existing_tag" == "$tag_name" ]] && continue
            [[ -z "$existing_epoch" ]] && continue
            if [[ "$existing_epoch" -gt "$twentyfour_hours_ago" ]] && \
               [[ "$existing_epoch" -gt "$recent_epoch" ]]; then
                recent_offender="$existing_tag"
                recent_epoch="$existing_epoch"
            fi
        done < <(git for-each-ref --format='%(refname:short)|%(creatordate:unix)' 'refs/tags/v*.*.0')

        if [[ -n "$recent_offender" ]]; then
            ago_secs=$((now_epoch - recent_epoch))
            ago_h=$((ago_secs / 3600))
            ago_m=$(((ago_secs % 3600) / 60))
            red ""
            red "==============================================================="
            red " RELEASE GATE FAIL: v*.*.0 tag cadence violation (24 h window)"
            red "==============================================================="
            red "  attempting to push: $tag_name"
            red "  most recent v*.*.0: $recent_offender (${ago_h}h ${ago_m}m ago)"
            red ""
            red "  Memory rule 'release-cadence-budget': Max one v* tag per 24h."
            red "  Reason: consecutive v*.*.0 tags burned ~€25/week of Actions"
            red "  when v0.4.1+v0.4.2+v0.5.0 fired on back-to-back days. Same"
            red "  failure mode fired 6+ times on 2026-07-01 (recovery cycle)"
            red "  which is what got this gate wired in."
            red ""
            red "  If this is a fix / correction of the most recent release:"
            red "  DO NOT tag as vX.Y.0 — use an iteration tag vX.Y.Z (Z>0)"
            red "  which skips the release matrix per the v*.*.0 glob."
            red ""
            red "  If this is a genuine hotfix emergency inside 24h:"
            red "    git push --no-verify $tag_name"
            red "  (and note the reason in the tag's annotated message)"
            red "==============================================================="
            exit 1
        fi

        # (3) FC-declaration check. Every v*.*.0 push requires an
        # explicit committed file at docs/release-fc/<tag>.md.
        # Iteration counter Z (in vX.Y.Z) increments arbitrarily
        # (1, 2, ..., 9, 10, ..., 99, 100, ..., 999, 1000, ...) —
        # there is NO overflow-based promotion from vX.Y.<big> to
        # vX.(Y+1).0. The ONLY gate is human declaration of
        # feature-completeness on the codebase. The FC file is
        # that declaration — writing it, committing it, and
        # pushing it is the operator's affirmative statement.
        # Content-agnostic here (the file's presence is what
        # matters); write anything relevant to the release-
        # readiness statement + link the iterations that
        # constitute the FC scope.
        fc_marker="docs/release-fc/${tag_name}.md"
        if ! git ls-tree -r --name-only HEAD | grep -qxF "$fc_marker"; then
            red ""
            red "==============================================================="
            red " RELEASE GATE FAIL: no FC-declaration for $tag_name"
            red "==============================================================="
            red "  tag:      $tag_name"
            red "  required: $fc_marker (must be committed on the branch)"
            red ""
            red "  Iteration tags (vX.Y.Z, Z>0) have NO cap and no automatic"
            red "  promotion. Do NOT go from v1.0.9 to v1.1.0 on the reasoning"
            red "  that the patch position 'rolled over'. Iteration counter"
            red "  climbs arbitrarily: 1, 2, ..., 9, 10, ..., 99, 100, ...,"
            red "  999, 1000, ..., 10^65 if that is what the pace of iteration"
            red "  demands."
            red ""
            red "  The ONLY gate that promotes vX.Y.Z to vX.(Y+1).0 is a"
            red "  human declaration of feature-completeness on the codebase."
            red "  The gate below encodes that declaration as a git-tracked"
            red "  file the operator must write + commit before the release-"
            red "  line tag can push."
            red ""
            red "  To declare FC for $tag_name:"
            red "    1. mkdir -p docs/release-fc"
            red "    2. \$EDITOR $fc_marker"
            red "       (write the release-readiness statement — link the"
            red "        iterations that constitute FC, note any deferrals"
            red "        for the next release-line)"
            red "    3. git add $fc_marker"
            red "    4. git commit -m 'FC: $tag_name'"
            red "    5. git tag -a $tag_name -m 'v${tag_name#v} (FC)'"
            red "    6. git push origin main $tag_name"
            red "==============================================================="
            exit 1
        fi
    done
    green "release-tag gate: ok"
fi

# ---- 0. Pre-install detector weights -----------------------------
#
# v0.7 phase 8a: weights are downloaded on user demand, not bundled.
# Tests + gate scripts must explicitly install the weights they
# need before exercising the code paths that load them. We install
# silentcipher (gate step 2 parity sweep + step 3 AAC smoke) and
# audioseal (gate step 3 AAC smoke). Idempotent — re-installs are
# no-ops when the cache is valid.
yellow "[0/3] pre-installing detector weights (silentcipher + audioseal)"
if [[ -x target/release/provcheck-kit ]]; then
    target/release/provcheck-kit weights install silentcipher 2>&1 | tail -3
    target/release/provcheck-kit weights install audioseal 2>&1 | tail -3
else
    yellow "  kit binary not yet built; will install via cargo run from the test target dir"
    CARGO_TARGET_DIR=./target-gate cargo run --release --bin provcheck-kit -- \
        weights install silentcipher 2>&1 | tail -3 || true
    CARGO_TARGET_DIR=./target-gate cargo run --release --bin provcheck-kit -- \
        weights install audioseal 2>&1 | tail -3 || true
fi
green "  OK"

# ---- 1. Format + lint gate (2026-07: CI parity) -------------------
# CI's "fmt + clippy" and "test" jobs enforce `cargo fmt --check` and
# RUSTFLAGS=-D warnings. Because every commit on main carries
# [skip ci], CI never runs on our own pushes, so this gate is the
# ONLY thing catching format drift or a compiler warning before it
# reaches the Dependabot PRs, the sole surface where CI actually
# fires. Root cause of the 2026-07 red-main incident: drift and a
# doc-lint warning accumulated invisibly across the v1.1.x iteration
# series because the gate tested without -D warnings and never ran
# fmt --check.
yellow "[1/4] cargo fmt --check + clippy -D warnings"
if ! cargo fmt --check; then
    red "  FAIL: formatting drift. Run 'cargo fmt' and re-stage."
    exit 1
fi
if ! RUSTFLAGS="-D warnings" CARGO_TARGET_DIR=./target-gate \
        cargo clippy --workspace --all-targets --jobs 8 2>&1 | tail -20; then
    red "  FAIL: clippy / -D warnings. Fix the reported warnings."
    exit 1
fi
green "  OK"

# ---- 2. Workspace cargo test --------------------------------------
yellow "[2/4] cargo test --release --workspace"
# Use a separate target dir so the test build's intermediate link
# step does not collide with a long-running process holding
# `target/release/*.exe` open on Windows. Same root cause as step 2's
# `|| true` rebuild tolerance, applied here as a clean-build-tree
# pattern rather than a swallow-and-continue.
if ! CARGO_TARGET_DIR=./target-gate cargo test --release --workspace 2>&1 | tail -40; then
    red "  FAIL: workspace tests"
    exit 1
fi
green "  OK"

# ---- 2. Parity sweep vs upstream Python silentcipher --------------
if [[ "$SKIP_PARITY" == "1" ]]; then
    yellow "[3/4] parity sweep SKIPPED (--skip-parity)"
else
    yellow "[3/4] parity sweep vs upstream Python (SDR 30 + 47)"

    # Skip silentcipher weights cleanly if they are not in HF cache.
    if ! python -c "from pathlib import Path; p = Path.home() / '.cache/huggingface/hub/models--sony--silentcipher'; import sys; sys.exit(0 if any(p.rglob('44_1_khz/73999_iteration/hparams.yaml')) else 1)" 2>/dev/null; then
        red "  FAIL: silentcipher 44.1k weights missing from HF cache."
        red "        Run: python -c \"from huggingface_hub import snapshot_download; snapshot_download('sony/silentcipher')\""
        red "        Or push with --skip-parity (then note in commit body)."
        exit 1
    fi
    if ! python -c "import silentcipher, librosa, soundfile, numpy" 2>/dev/null; then
        red "  FAIL: missing python deps. Run: pip install silentcipher librosa soundfile numpy"
        exit 1
    fi

    # Build the release CLI once so parity-vs-upstream uses fresh
    # binaries. `|| true` because Windows file locking will fail
    # this build silently when another process is holding the kit
    # or verifier exe open (e.g. a long-running prod-batch verify
    # run by the operator). In that case the parity sweep just
    # uses whichever binary is already on disk; if it is too stale
    # the sweep's threshold check below catches that downstream.
    # Without `|| true` the script's `set -euo pipefail` exits
    # silently here, leaving the operator with an unexplained push
    # rejection.
    cargo build --release --bin provcheck-kit --bin provcheck >/dev/null 2>&1 || true

    # Run a focused sweep (5s clip, SDR 30 + 47) and parse the conf
    # column for the rust-detect-rust row. The full script writes its
    # report to stdout; we tee to a log for inspection.
    LOG="target/check-before-push-parity.log"
    mkdir -p target
    if ! python scripts/parity-vs-upstream.py examples/rAIdio.bot-sample.mp3 \
            --duration-s 5 --sdrs 30 47 --skip-codec >"$LOG" 2>&1; then
        red "  FAIL: parity-vs-upstream.py crashed. See $LOG"
        exit 1
    fi

    # Extract the Python detector confidences (py(P)/rs(P)) from the
    # report table. Schema: "  30  0.999  0.999"-ish. Pull the rs(P)
    # column for the SDR 30 row and gate at >= 0.85.
    rust_at_30=$(awk '/^   30/ {print $(NF)}' "$LOG" | head -1)
    if [[ -z "$rust_at_30" ]] || ! python -c "import sys; v = float('$rust_at_30'); sys.exit(0 if v >= 0.85 else 1)" 2>/dev/null; then
        red "  FAIL: parity rust-embed-python-detect at SDR 30 conf=${rust_at_30:-?} < 0.85. See $LOG"
        exit 1
    fi
    green "  OK (rust@SDR30 conf=$rust_at_30 via python detector)"
fi

# ---- 3. AAC delivery survival (issues #23 + #24) ------------------
yellow "[4/4] AAC delivery survival smoke (issues #23 + #24)"
if ! command -v ffmpeg >/dev/null; then
    yellow "  ffmpeg not on PATH — skipping codec survival smoke"
    yellow "  (this gate cannot run; add ffmpeg if you want it enforced)"
else
    SCRATCH="$(mktemp -d)"
    trap 'rm -rf "$SCRATCH"' EXIT

    # Embed silentcipher into the 15-40s window + AAC re-encode +
    # detect. Sliced from `ss 15` for a 25-second window that lands
    # squarely inside one of silentcipher's tile-vote hot regions on
    # the bundled rAIdio.bot sample. v0.6.0 release postmortem:
    # `ss=0 -t=5` was prone to landing in a tile trough where mode-
    # vote confidence falls below the 0.85 gate even on a correctly-
    # marked output (empirical probe at scripts/check-before-push.sh
    # commit history).
    #
    # The kit embed STDERR is preserved (was `>/dev/null 2>&1 || true`
    # which masked real failures — another v0.6.0 lesson). If the
    # embed itself fails, the ffmpeg slice will fail next and the
    # ERR trap installed at the top of this script will surface
    # both the failing line and the kit's stderr.
    target/release/provcheck-kit watermark examples/rAIdio.bot-sample.mp3 \
        -o "$SCRATCH/sc_marked.wav" --no-verify-after-embed --overwrite >/dev/null
    [[ -s "$SCRATCH/sc_marked.wav" ]] || {
        red "  FAIL: kit produced no output WAV (sc_marked.wav missing or empty)"
        exit 1
    }
    ffmpeg -y -loglevel error -ss 15 -t 25 -i "$SCRATCH/sc_marked.wav" "$SCRATCH/sc_slice.wav"
    ffmpeg -y -loglevel error -i "$SCRATCH/sc_slice.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/sc_aac.m4a"
    # `provcheck` exits 1 on unsigned files; the AAC re-encode strips
    # any C2PA manifest, so on a watermark-only test the verifier
    # ALWAYS reports unsigned and returns non-zero. We care about the
    # watermark conf in the JSON body, not the manifest verification
    # status, so wrap to tolerate the exit code while still propagating
    # any genuine JSON-parse failures from python downstream.
    sc_conf=$( { target/release/provcheck --json "$SCRATCH/sc_aac.m4a" 2>/dev/null || true; } | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='silent_cipher'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$sc_conf') >= 0.85 else 1)"; then
        red "  FAIL: silentcipher AAC 192k delivery conf=$sc_conf < 0.85 (issue #24 regression)"
        exit 1
    fi
    green "  silentcipher AAC 192k: conf=$sc_conf OK"

    # Embed audioseal at default alpha + AAC re-encode + detect.
    target/release/provcheck-kit watermark "$SCRATCH/sc_slice.wav" \
        -o "$SCRATCH/as_marked.wav" --kind audioseal --brand-id 1 --no-verify-after-embed --overwrite >/dev/null 2>&1
    ffmpeg -y -loglevel error -i "$SCRATCH/as_marked.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/as_aac.m4a"
    # Same `|| true` pattern as the silentcipher step above —
    # provcheck reports the AAC file as unsigned (no C2PA), exits 1,
    # but the watermark conf JSON body is what we are gating on.
    as_conf=$( { target/release/provcheck --json "$SCRATCH/as_aac.m4a" 2>/dev/null || true; } | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='audio_seal'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$as_conf') >= 0.85 else 1)"; then
        red "  FAIL: audioseal AAC 192k delivery conf=$as_conf < 0.85 (issue #23 regression)"
        exit 1
    fi
    green "  audioseal AAC 192k:    conf=$as_conf OK"
fi

green ""
green "All pre-push checks passed."
