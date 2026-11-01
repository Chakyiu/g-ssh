# Builds g-ssh-<version>-windows-x86_64.msi from a folder that already
# holds g-ssh.exe and update.exe. WiX is installed with:
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add -g WixToolset.UI.wixext/5.0.2
param(
    [Parameter(Mandatory = $true)][string] $Version,
    [Parameter(Mandatory = $true)][string] $PayloadDir,
    [Parameter(Mandatory = $true)][string] $Output
)

$ErrorActionPreference = "Stop"

$wix = Get-Command wix -ErrorAction SilentlyContinue
if ($wix) {
    $wix = $wix.Source
} else {
    $wix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
}
if (-not (Test-Path -LiteralPath $wix)) {
    throw "wix is not installed. Run: dotnet tool install --global wix --version 5.0.2"
}

$parts = @($Version.Split('.') | Where-Object { $_ -ne "" })
while ($parts.Count -lt 4) {
    $parts += "0"
}
$msiVersion = ($parts[0..3] -join ".")

$here = Split-Path -Parent $PSCommandPath
$source = Join-Path $here "..\packaging\windows\Package.wxs"
$payload = (Resolve-Path -LiteralPath $PayloadDir).Path
$uiExt = "WixToolset.UI.wixext/5.0.2"

# WiX exits 2 when the cache lists nothing. A fresh machine has no
# extensions yet, so that code means "not installed", not a broken wix.
$listed = & $wix extension list -g
$listCode = $LASTEXITCODE
if ($listCode -ne 0 -and $listCode -ne 2) {
    throw "wix extension list failed with exit code $listCode"
}
$haveUi = ($listCode -eq 0) -and (($listed | Out-String) -match "WixToolset\.UI\.wixext\s+5\.0\.2(?!\s+\(damaged\))")
if (-not $haveUi) {
    & $wix extension add -g $uiExt
    if ($LASTEXITCODE -ne 0) {
        throw "wix extension add failed with exit code $LASTEXITCODE"
    }
}

& $wix build -ext $uiExt $source -d "Version=$msiVersion" -d "PayloadDir=$payload" -o $Output
if ($LASTEXITCODE -ne 0) {
    throw "wix build failed with exit code $LASTEXITCODE"
}
