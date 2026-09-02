# stage-gui-resources.ps1 - assemble the Windows GUI's bundled resource
# folders (backfire/, mellin/, test-files/) under app/src-tauri/.
#
# tauri.windows.conf.json bundles these three folders into the installer,
# but they are BUILD ARTIFACTS (gitignored), so both CI and a fresh local
# checkout must assemble them before `tauri build`. This script is the one
# place that knows how; release.yml's windows-gui job calls it, and a local
# operator can run it directly.
#
# It also GENERATES the Mellin sample pair from the committed source track
# and verifies both reads, so every release build carries a keyed-read
# end-to-end test as a side effect. Any verification failure exits 1.
#
# Runs one cargo build (provcheck-mellin, standalone crate). Respect the
# one-cargo-at-a-time convention locally.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail([string]$m) { Write-Error "stage-gui-resources: $m"; exit 1 }

# ---- 1. backfire/ (reader code + self-contained Python) -------------------
Write-Host "== staging backfire/ =="
$bfDst = "app/src-tauri/backfire"
robocopy backfire $bfDst /E /XD pyembed __pycache__ .pytest_cache /NDL /NJH /NJS /NFL | Out-Null
if ($LASTEXITCODE -gt 3) { Fail "robocopy backfire failed ($LASTEXITCODE)" }
if (Test-Path "$bfDst/pyembed/python.exe") {
    Write-Host "pyembed already present; skipping setup"
} else {
    # Downloads the pinned embeddable CPython + numpy/pillow and smoke-tests
    # a known marked image (read id 0x7). Needs python.org + PyPI once.
    & powershell -NoProfile -ExecutionPolicy Bypass -File "$bfDst/setup_backfire.ps1" -Quiet
    if ($LASTEXITCODE -ne 0) { Fail "setup_backfire.ps1 failed ($LASTEXITCODE)" }
}
if (-not (Test-Path "$bfDst/pyembed/python.exe")) { Fail "pyembed missing after setup" }

# ---- 2. mellin/ (standalone binary + its license set) ---------------------
Write-Host "== staging mellin/ =="
cargo build --manifest-path crates/provcheck-mellin/Cargo.toml --release
if ($LASTEXITCODE -ne 0) { Fail "provcheck-mellin build failed" }
$mlDst = "app/src-tauri/mellin"
New-Item -ItemType Directory -Force $mlDst | Out-Null
$mlSrc = "crates/provcheck-mellin"
Copy-Item "$mlSrc/target/release/provcheck-mellin.exe" $mlDst -Force
foreach ($f in @("LICENSE","LICENSING.md","EULA.md","TOS.md","README.md")) {
    Copy-Item "$mlSrc/$f" $mlDst -Force
}

# ---- 3. test-files/ (samples; Mellin pair generated + verified) -----------
Write-Host "== staging test-files/ =="
$tfDst = "app/src-tauri/test-files"
New-Item -ItemType Directory -Force $tfDst | Out-Null
Copy-Item "backfire/repro/sample_marked.png"   "$tfDst/backfire-marked.png"   -Force
Copy-Item "backfire/repro/sample.png"          "$tfDst/backfire-unmarked.png" -Force
Copy-Item "examples/keyed-samples/rAIdio.bot-signed-sample.mp3" $tfDst -Force
Copy-Item "examples/keyed-samples/mellin-secret.txt"            $tfDst -Force
Copy-Item "examples/keyed-samples/test-files-README.txt" "$tfDst/README.txt"  -Force

$MB = "$mlSrc/target/release/provcheck-mellin.exe"
$SEC = "$tfDst/mellin-secret.txt"
$SRC = "$tfDst/rAIdio.bot-signed-sample.mp3"
& $MB embed --secret-file $SEC --work-id album-x --serial 0xC0FFEE1234 --repeat 8 --strength 0.35 $SRC -o "$tfDst/mellin-marked.wav"
if ($LASTEXITCODE -ne 0) { Fail "mellin embed (marked) failed" }
& $MB embed --secret-file $SEC --work-id album-x --serial 0x0 --strength 0 $SRC -o "$tfDst/mellin-unmarked.wav"
if ($LASTEXITCODE -ne 0) { Fail "mellin embed (unmarked passthrough) failed" }

Write-Host "== verifying the generated pair (release-pipeline keyed E2E) =="
$mj = & $MB read "$tfDst/mellin-marked.wav" --secret-file $SEC --work-id album-x --expect 0xC0FFEE1234 --json
$m = $mj | ConvertFrom-Json
if (-not $m.fully_recovered -or $m.match -ne $true) { Fail "marked sample failed verification: $mj" }
$uj = & $MB read "$tfDst/mellin-unmarked.wav" --secret-file $SEC --work-id album-x --json
$u = $uj | ConvertFrom-Json
if ($u.bits_recovered -ne 0) { Fail "unmarked control unexpectedly recovered bits: $uj" }
Write-Host "marked: $($m.serial) 64/64 match; unmarked: 0/64 (correct)"

Write-Host ""
Write-Host "GUI resources staged: backfire/, mellin/, test-files/ under app/src-tauri/"
exit 0
