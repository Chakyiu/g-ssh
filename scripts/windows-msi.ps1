# Builds g-ssh-<version>-windows-x86_64.msi from a folder that already
# holds g-ssh.exe and update.exe. WiX is installed with:
#   dotnet tool install --global wix --version 5.0.2
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

& $wix build $source -d "Version=$msiVersion" -d "PayloadDir=$payload" -o $Output
if ($LASTEXITCODE -ne 0) {
    throw "wix build failed with exit code $LASTEXITCODE"
}
