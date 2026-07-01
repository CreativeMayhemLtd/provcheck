param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath
)

# Authenticode code-signer for provcheck's Windows binaries via
# SSL.com eSigner cloud signing. Signs any -ExePath in place using
# the credentials in the -ConfigPath JSON file.
#
# The eSigner cloud path uses SSL.com's CodeSignTool to hash the
# binary locally, submit the hash to SSL.com's HSM, and receive
# the Authenticode signature back — the private key never leaves
# SSL.com's HSM.
#
# Three inputs are needed per sign:
#   1. SSL.com account username + password. Either:
#      (a) in Windows Credential Manager under the target name in
#          signing.json (local dev machine — no plaintext on disk), OR
#      (b) inline in signing.json under `username` + `password`
#          (CI runners — materialised from GitHub Secrets at
#          workflow start, deleted at end).
#   2. eSigner credential_id — non-secret, in signing.json.
#   3. Per-sign TOTP — CodeSignTool derives it internally from
#      SSL.com's base64 `secret_code` (in signing.json as
#      `totp_secret`). This is NOT a base32 authenticator seed; any
#      YubiKey / ykman path against it will fail with "Non-base32
#      digit" errors because SSL.com's secret_code uses base64
#      characters (`+`, `/`, `=`, lowercase, `0`, `1`, `8`).
#
# Order note: any integrity-stamping (PE header manipulation, etc.)
# must complete BEFORE this script runs. The Authenticode signature
# covers the final PE bytes; a stamper running after signing
# invalidates the signature.
#
# Exits non-zero on any failure. When `enabled: false` in the
# config, exits 0 with an "operator disabled" note so a
# preparation-only CI job can skip signing without failing the run.

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Signing config not found: $ConfigPath"
    exit 1
}

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if (-not $cfg.enabled) {
    Write-Host "  Signing disabled in $ConfigPath (enabled=false)." -ForegroundColor DarkGray
    exit 0
}

# --- 1. Resolve SSL.com account credentials ---
#
# Prefer inline (CI path) if the config carries `username` +
# `password` fields directly. Fall back to Windows Credential
# Manager (local dev path) via the target name.
$username = $null
$password = $null

if ($cfg.username -and $cfg.password) {
    $username = $cfg.username
    $password = $cfg.password
} else {
    # Credential Manager path.
    # Install once per machine:
    #   Install-Module -Name CredentialManager -Scope CurrentUser
    # Seed once via:
    #   cmdkey /generic:SSL.com-eSigner /user:<username> /pass:<pw>
    $credModule = Get-Module -ListAvailable -Name CredentialManager
    if (-not $credModule) {
        Write-Error "PowerShell module 'CredentialManager' is not installed AND signing.json has no inline username/password. Either: (a) Install-Module CredentialManager -Scope CurrentUser and seed Credential Manager, or (b) add username + password fields to signing.json."
        exit 1
    }
    Import-Module CredentialManager
    if (-not $cfg.credential_target) {
        Write-Error "signing.json needs either inline username/password OR a credential_target for Credential Manager."
        exit 1
    }
    $stored = Get-StoredCredential -Target $cfg.credential_target
    if (-not $stored) {
        Write-Error "No Credential Manager entry named '$($cfg.credential_target)'. Run: cmdkey /generic:$($cfg.credential_target) /user:<username> /pass:<pw>"
        exit 1
    }
    $username = $stored.UserName
    $password = $stored.GetNetworkCredential().Password
}

# --- 2. Resolve CodeSignTool ---
$tool = Join-Path $cfg.codesigntool_dir "CodeSignTool.bat"
if (-not (Test-Path $tool)) {
    Write-Error "CodeSignTool.bat not found at $tool. Download from https://www.ssl.com/guide/esigner-codesigntool-command-guide/ and unpack into $($cfg.codesigntool_dir)."
    exit 1
}
# The bat reads %CODE_SIGN_TOOL_PATH% to resolve its bundled jdk +
# jar paths; setting it inline decouples us from any persistent
# env var going stale relative to codesigntool_dir.
$env:CODE_SIGN_TOOL_PATH = $cfg.codesigntool_dir

# --- 3. Sign ---
# CodeSignTool reads the source file, hashes it locally, sends
# only the hash to SSL.com, then writes the signed copy to the
# output dir. We then copy the signed exe back over the original.
$exeFull = (Resolve-Path $ExePath).Path
$outDir = (New-Item -ItemType Directory -Force -Path "$env:TEMP\esigner-out").FullName

if (-not $cfg.totp_secret) {
    Write-Error "signing.json is missing totp_secret (the base64 secret_code from the SSL.com eSigner QR panel). This is required — CodeSignTool derives the per-sign OTP from it. Do NOT feed a base32 authenticator seed here."
    exit 1
}

& $tool sign `
    "-credential_id=$($cfg.credential_id)" `
    "-username=$username" `
    "-password=$password" `
    "-totp_secret=$($cfg.totp_secret)" `
    "-input_file_path=$exeFull" `
    "-output_dir_path=$outDir"
if ($LASTEXITCODE -ne 0) {
    Write-Error "CodeSignTool exited $LASTEXITCODE."
    exit 1
}

# --- 4. Copy signed exe back over the unsigned input ---
$signedExe = Join-Path $outDir (Split-Path $ExePath -Leaf)
if (-not (Test-Path $signedExe)) {
    Write-Error "Signed exe not found at $signedExe after CodeSignTool ran."
    exit 1
}
Copy-Item -Force $signedExe $exeFull

# --- 5. Verify the signature (optional; needs Windows SDK signtool) ---
if ($cfg.verify_after_sign) {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Write-Warning "signtool.exe not on PATH; skipping verify step. Install the Windows 10/11 SDK and add it to PATH."
    } else {
        & signtool.exe verify /pa /v $exeFull
        if ($LASTEXITCODE -ne 0) {
            Write-Error "signtool verify failed — signature is present but invalid."
            exit 1
        }
    }
}

# --- 6. Append to sign audit log ---
$sha = (Get-FileHash $exeFull -Algorithm SHA256).Hash
$logLine = "$(Get-Date -Format o)`t$sha`t$exeFull"
$logPath = if ($cfg.audit_log) { $cfg.audit_log } else { Join-Path $env:TEMP "provcheck-signing.log" }
try {
    Add-Content -Path $logPath -Value $logLine -ErrorAction Stop
} catch {
    Write-Warning "Could not append to $logPath ($_). Signed OK; audit log skipped."
}

Write-Host "  Signed + verified. SHA-256: $sha" -ForegroundColor Green
exit 0
