# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
#
# setup_backfire.ps1 - one-command Backfire environment installer (Windows).
#
# Read tier (default): stands up a fully self-contained Python for Backfire's
# numpy-only READ path, so verification works on a clean box with no system
# Python. Downloads the official Windows embeddable CPython, makes it
# pip-capable, installs numpy and pillow, and smoke-tests a known marked image.
#
# Embed tier (-Embed): additionally installs torch, diffusers, and transformers
# and pre-fetches the diffusion and TrustMark weights the GPU embed path needs.
# This is large (multiple GB) and is for creators, not verifiers.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File setup_backfire.ps1            # read tier
#   powershell -ExecutionPolicy Bypass -File setup_backfire.ps1 -Embed     # + embed tier
#   powershell -ExecutionPolicy Bypass -File setup_backfire.ps1 -Force     # rebuild from scratch
#
# Exit codes: 0 success, 1 failure (message on stderr).

[CmdletBinding()]
param(
    [switch]$Embed,
    [switch]$Force,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pinned so a clean box is reproducible. Bump deliberately.
$PyVersion   = '3.11.9'
$PyZipName   = "python-$PyVersion-embed-amd64.zip"
$PyZipUrl    = "https://www.python.org/ftp/python/$PyVersion/$PyZipName"
$GetPipUrl   = 'https://bootstrap.pypa.io/get-pip.py'
$PthName     = 'python311._pth'

$BackfireDir = $PSScriptRoot
$PyEmbedDir  = Join-Path $BackfireDir 'pyembed'
$PyExe       = Join-Path $PyEmbedDir 'python.exe'
$BackfirePy  = Join-Path $BackfireDir 'backfire.py'
$SamplePng   = Join-Path $BackfireDir 'repro\sample_marked.png'
$ReadMarker  = Join-Path $PyEmbedDir '.read-ready'
$EmbedMarker = Join-Path $PyEmbedDir '.embed-ready'

function Say([string]$m)  { if (-not $Quiet) { Write-Host $m } }
function Step([string]$m) { if (-not $Quiet) { Write-Host "==> $m" } }
function Die([string]$m)  { Write-Error "setup_backfire: $m"; exit 1 }

if (-not (Test-Path $BackfirePy)) {
    Die "backfire.py not found next to this script ($BackfirePy). Run this from inside the backfire folder."
}

# --- Read tier: self-contained embeddable Python + numpy + pillow ---------

$readReady = (Test-Path $PyExe) -and (Test-Path $ReadMarker)
if ($Force -and (Test-Path $PyEmbedDir)) {
    Step "Force: removing existing pyembed"
    Remove-Item -Recurse -Force $PyEmbedDir
    $readReady = $false
}

if (-not $readReady) {
    Step "Setting up self-contained Python $PyVersion for the Backfire read path"
    New-Item -ItemType Directory -Force -Path $PyEmbedDir | Out-Null

    $tmpZip = Join-Path $env:TEMP $PyZipName
    Step "Downloading embeddable Python ($PyZipUrl)"
    Invoke-WebRequest -Uri $PyZipUrl -OutFile $tmpZip -UseBasicParsing
    Step "Extracting"
    Expand-Archive -Path $tmpZip -DestinationPath $PyEmbedDir -Force
    Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue

    # Make the embeddable interpreter honor site-packages: the ._pth ships with
    # "#import site" commented out, which hides anything pip installs. Uncomment
    # it. This is the one non-obvious step in the whole setup.
    $pth = Join-Path $PyEmbedDir $PthName
    if (-not (Test-Path $pth)) { Die "expected $PthName in the embeddable zip, not found" }
    $pthText = Get-Content $pth -Raw
    $pthText = $pthText -replace '(?m)^\s*#\s*import site\s*$', 'import site'
    if ($pthText -notmatch '(?m)^\s*import site\s*$') { $pthText = $pthText.TrimEnd() + "`r`nimport site`r`n" }
    Set-Content -Path $pth -Value $pthText -Encoding Ascii -NoNewline

    $getPip = Join-Path $PyEmbedDir 'get-pip.py'
    Step "Bootstrapping pip"
    Invoke-WebRequest -Uri $GetPipUrl -OutFile $getPip -UseBasicParsing
    & $PyExe $getPip --no-warn-script-location --quiet
    if ($LASTEXITCODE -ne 0) { Die "pip bootstrap failed" }

    Step "Installing read dependencies (numpy, pillow)"
    & $PyExe -m pip install --no-warn-script-location --quiet 'numpy>=1.24' 'pillow>=10'
    if ($LASTEXITCODE -ne 0) { Die "installing numpy/pillow failed" }
} else {
    Step "Read environment already present (use -Force to rebuild)"
}

# --- Smoke test the read path against a known marked image ----------------

Step "Smoke-testing the Backfire read path"
if (-not (Test-Path $SamplePng)) { Die "sample image missing ($SamplePng)" }
$raw = & $PyExe $BackfirePy read $SamplePng --key 'backfire-demo-key' 2>$null
$jsonLine = ($raw | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1)
try { $res = $jsonLine | ConvertFrom-Json } catch { Die "read produced no JSON. Output was: $raw" }
if (-not $res.valid) { Die "smoke test FAILED: expected a valid mark, got valid=$($res.valid) margin=$($res.min_bit_margin)" }
if ($res.id_hex -ne '0x7') { Die "smoke test FAILED: expected id 0x7, got $($res.id_hex)" }
New-Item -ItemType File -Force -Path $ReadMarker | Out-Null
Say ""
Say "Backfire read path is ready. Verified: sample_marked.png -> id $($res.id_hex), valid, margin $([math]::Round($res.min_bit_margin,2))."

# --- Embed tier (opt-in): torch + diffusers + model weights ---------------

if ($Embed) {
    Step "Embed tier: installing torch, diffusers, transformers (large download)"
    & $PyExe -m pip install --no-warn-script-location 'torch' 'diffusers>=0.27' 'transformers>=4.40' 'huggingface_hub'
    if ($LASTEXITCODE -ne 0) { Die "installing embed dependencies failed" }
    Say "  Note: this installed the default (CPU) torch wheel. For GPU embed, install a CUDA torch build for your platform (see pytorch.org) into $PyEmbedDir."

    Step "Pre-fetching the diffusion purifier and TrustMark weights (several GB)"
    $fetch = @'
import sys
from huggingface_hub import snapshot_download
# SD-2.1 base community mirror, pinned revision (Stability withdrew the original).
snapshot_download("huanzi05/stable-diffusion-2-1-base",
                  revision="f71d7867a2745c420aa93441638b119c85995963")
print("models fetched")
'@
    $fetch | & $PyExe -
    if ($LASTEXITCODE -ne 0) { Die "model pre-fetch failed (network or Hugging Face reachability)" }
    New-Item -ItemType File -Force -Path $EmbedMarker | Out-Null
    Say ""
    Say "Backfire embed tier is ready (torch + diffusion weights installed)."
}

Say ""
Say "Done. provcheck will now find this environment automatically."
exit 0
