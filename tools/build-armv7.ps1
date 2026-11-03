param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArgs
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:CC_armv7_unknown_linux_musleabihf = Join-Path $root "tools\cross\zig-cc.cmd"
$env:AR_armv7_unknown_linux_musleabihf = Join-Path $root "tools\cross\zig-ar.cmd"

& cargo build -p mngd --release --target armv7-unknown-linux-musleabihf @CargoArgs
exit $LASTEXITCODE
