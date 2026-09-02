<#
.SYNOPSIS
  Local sign + publish for a provcheck release (rAIdio.bot credential convention).

.DESCRIPTION
  Signs the CI-built (unsigned) release artifacts locally and attaches them to
  the GitHub release. Credentials live in the gitignored `signing.json` at the
  repo root and the minisign key at $PROVCHECK_MINISIGN_KEY, never in GitHub
  Secrets, never on a command line, never logged.

  Signing policy:
    * Windows .exe / .msi (loose, and the .exe inside each *-windows-x86_64.zip)
      -> Authenticode via SSL.com eSigner (scripts/sign_release.ps1 + signing.json).
    * Non-Windows binaries (.deb / .AppImage / .dmg / *-linux-* / *-macos-* .tar.gz)
      -> detached minisign (.minisig) via rsign (rsign2), passwordless key.
    * SBOMs (.cdx.json / .spdx.json) -> .sha256 sidecar only.

  Re-generates the .sha256 sidecar for any file it re-creates (signed installers
  and re-zipped archives), verifies fail-closed (every Windows binary must be
  Authenticode-Valid, every Linux/macOS binary must have a .minisig), then
  uploads the full set with `gh release upload --clobber`.

.PARAMETER DistDir
  Directory holding the downloaded workflow artifacts (from `gh run download`).

.PARAMETER Tag
  Release tag to attach to, e.g. v1.1.0.

.EXAMPLE
  gh run download <run-id> --repo CreativeMayhemLtd/provcheck --dir C:\path\to\dist
  scripts\sign-and-publish-release.ps1 -DistDir C:\path\to\dist -Tag vX.Y.0
#>
param(
  [Parameter(Mandatory = $true)][string]$DistDir,
  [Parameter(Mandatory = $true)][string]$Tag,
  [string]$Repo = "CreativeMayhemLtd/provcheck",
  [string]$SigningConfig = (Join-Path $PSScriptRoot "..\signing.json"),
  [string]$MinisignKey = $env:PROVCHECK_MINISIGN_KEY,
  [switch]$SkipUpload
)

$ErrorActionPreference = "Stop"
$signer = Join-Path $PSScriptRoot "sign_release.ps1"

if (-not (Test-Path $SigningConfig)) { throw "signing.json not found at $SigningConfig (gitignored; copy from the signing identity)." }
if (-not (Test-Path $MinisignKey))   { throw "minisign key not found at $MinisignKey." }

function Regen-Sha([string]$path) {
  $sha = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLower()
  $name = [System.IO.Path]::GetFileName($path)
  # Match the `sha256sum` output format the CI stage step writes.
  [System.IO.File]::WriteAllText("$path.sha256", "$sha  $name`n")
}
function Is-AuthenticodeValid([string]$path) {
  try { (Get-AuthenticodeSignature $path).Status -eq 'Valid' } catch { $false }
}
function Minisign([string]$path) {
  & rsign sign -W -s $MinisignKey -x "$path.minisig" $path
  if ($LASTEXITCODE -ne 0) { throw "rsign failed on $path" }
}
function Is-NonWinBinary([string]$name) {
  return ($name -match '\.(deb|AppImage|dmg)$') -or ($name -match '-(linux|macos)-[^.]+\.tar\.gz$')
}

$payload = Get-ChildItem $DistDir -Recurse -File | Where-Object { $_.Name -notmatch '\.(sha256|minisig)$' }

foreach ($f in $payload) {
  $p = $f.FullName; $n = $f.Name
  if ($n -match '\.(exe|msi)$') {
    if (Is-AuthenticodeValid $p) { Write-Host "  already signed: $n" }
    else { Write-Host "  authenticode:   $n"; & $signer -ExePath $p -ConfigPath $SigningConfig | Out-Null }
    Regen-Sha $p
  }
  elseif ($n -match '-windows-x86_64\.zip$') {
    Write-Host "  authenticode (in zip): $n"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("resign_" + [guid]::NewGuid().ToString('N'))
    Expand-Archive -Path $p -DestinationPath $tmp -Force
    Get-ChildItem $tmp -Recurse -Filter *.exe | ForEach-Object {
      if (-not (Is-AuthenticodeValid $_.FullName)) { & $signer -ExePath $_.FullName -ConfigPath $SigningConfig | Out-Null }
    }
    Remove-Item -Force $p
    $top = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Compress-Archive -Path $top.FullName -DestinationPath $p -Force
    Remove-Item -Recurse -Force $tmp
    Regen-Sha $p
  }
  elseif (Is-NonWinBinary $n) {
    Write-Host "  minisign:       $n"
    Minisign $p
  }
  else {
    Write-Host "  sha256 only:    $n"
  }
}

Write-Host "`n=== fail-closed verification ==="
$bad = @()
foreach ($f in (Get-ChildItem $DistDir -Recurse -File)) {
  if ($f.Name -match '\.(exe|msi)$' -and -not (Is-AuthenticodeValid $f.FullName)) {
    $bad += "UNSIGNED (Authenticode): $($f.Name)"
  }
  if ((Is-NonWinBinary $f.Name) -and -not (Test-Path "$($f.FullName).minisig")) {
    $bad += "MISSING .minisig: $($f.Name)"
  }
}
if ($bad.Count -gt 0) {
  $bad | ForEach-Object { Write-Warning $_ }
  throw "signing verification FAILED (fail-closed) — refusing to publish."
}
Write-Host "OK: every Windows exe/msi is Authenticode-Valid; every Linux/macOS binary has a .minisig."

if ($SkipUpload) { Write-Host "`n-SkipUpload set; not uploading."; return }

Write-Host "`n=== upload to release $Tag ==="
$all = (Get-ChildItem $DistDir -Recurse -File).FullName
& gh release upload $Tag @all --repo $Repo --clobber
if ($LASTEXITCODE -ne 0) { throw "gh release upload failed" }
Write-Host "uploaded $($all.Count) files to $Tag on $Repo"
