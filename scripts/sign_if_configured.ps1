<#
.SYNOPSIS
  Tauri bundle.windows.signCommand hook: Authenticode-sign -ExePath during bundling
  IF the local signing.json is present, otherwise skip cleanly.

.DESCRIPTION
  Wired as Tauri's signCommand so the GUI exe AND the NSIS/MSI installers are signed
  as they are produced (the exe inside the installer is signed, not only the outer
  installer). Signing only happens on the signing box, where signing.json (the SSL.com
  eSigner credentials) lives; CI has no credentials and builds unsigned, so this
  wrapper exits 0 without signing when signing.json is absent, rather than failing the
  build. Locating both the wrapper's sibling sign_release.ps1 and the repo-root
  signing.json via $PSScriptRoot makes it independent of the working directory Tauri
  invokes it from.
#>
param([Parameter(Mandatory = $true)][string]$ExePath)
$ErrorActionPreference = "Stop"

$cfg = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "signing.json"
if (-not (Test-Path $cfg)) {
    Write-Host "sign_if_configured: no signing.json present, leaving unsigned: $ExePath"
    exit 0
}
& (Join-Path $PSScriptRoot "sign_release.ps1") -ExePath $ExePath -ConfigPath $cfg
