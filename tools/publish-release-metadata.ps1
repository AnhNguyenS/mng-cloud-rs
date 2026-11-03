#!/usr/bin/env pwsh
<#
.SYNOPSIS
Publish signed release metadata to the GitHub Pages branch.

.DESCRIPTION
Run this on the offline signing machine after `mng-sign release` produced a
signed release directory. The script verifies the signatures again, copies the
four metadata files to `releases/current/` and `releases/<version>/`, and pushes
the gh-pages branch. The private signing key is never read by this script.

A version directory is immutable: publishing the same version with different
bytes is refused. `releases/current/` may move forward to a higher sequence.

.PARAMETER ReleaseDir
Directory containing release.json, release.sig, manifest.json and manifest.sig.

.PARAMETER Repo
GitHub repository in owner/name form. Defaults to the production repository.

.PARAMETER NoPush
Clone and update the branch locally, then print the commit without pushing.
Useful for reviewing the result.

.EXAMPLE
pwsh tools/publish-release-metadata.ps1 -ReleaseDir dist/release
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseDir,

    [string]$Repo = 'AnhNguyenS/mng-cloud-rs',
    [string]$Branch = 'gh-pages',
    [string]$PublicKey = '',
    [switch]$NoPush
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $PublicKey) {
    $PublicKey = Join-Path $root 'ops/update-public.jwk'
}
$releasePath = (Resolve-Path $ReleaseDir).Path
$files = @('release.json', 'release.sig', 'manifest.json', 'manifest.sig')
foreach ($name in $files) {
    if (-not (Test-Path (Join-Path $releasePath $name) -PathType Leaf)) {
        throw "missing $name in $releasePath"
    }
}

$release = Get-Content (Join-Path $releasePath 'release.json') -Raw | ConvertFrom-Json
if ($release.schema -ne 1) { throw "unsupported release schema $($release.schema)" }
if ($release.version -notmatch '^\d+(?:\.\d+){1,3}$') { throw "invalid release version $($release.version)" }
if ($release.sequence -lt 1) { throw "invalid release sequence $($release.sequence)" }

Push-Location $root
try {
    & cargo run -q -p mng-sign -- verify-release --dir $releasePath --public-key $PublicKey
    if ($LASTEXITCODE -ne 0) { throw 'signature verification failed; refusing to publish' }
}
finally {
    Pop-Location
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("mng-pages-" + [guid]::NewGuid().ToString('N'))
try {
    & git clone --quiet --depth 1 --branch $Branch "git@github.com:$Repo.git" $temp
    if ($LASTEXITCODE -ne 0) { throw "cannot clone $Repo ($Branch)" }

    $versionDir = Join-Path $temp "releases/$($release.version)"
    $currentDir = Join-Path $temp 'releases/current'
    $versionExisted = Test-Path $versionDir
    New-Item -ItemType Directory -Force -Path $versionDir, $currentDir | Out-Null

    if ($versionExisted) {
        foreach ($name in $files) {
            $existing = Join-Path $versionDir $name
            if (-not (Test-Path $existing -PathType Leaf)) {
                throw "releases/$($release.version) is incomplete (missing $name); fix the branch by hand"
            }
            $a = (Get-FileHash $existing -Algorithm SHA256).Hash
            $b = (Get-FileHash (Join-Path $releasePath $name) -Algorithm SHA256).Hash
            if ($a -ne $b) {
                throw "releases/$($release.version)/$name already exists with different bytes; bump the version"
            }
        }
    }

    foreach ($name in $files) {
        Copy-Item (Join-Path $releasePath $name) (Join-Path $versionDir $name) -Force
        Copy-Item (Join-Path $releasePath $name) (Join-Path $currentDir $name) -Force
    }

    & git -C $temp add --all
    if ($LASTEXITCODE -ne 0) { throw 'git add failed' }
    & git -C $temp diff --cached --quiet
    $changed = $LASTEXITCODE -ne 0
    if (-not $changed) {
        Write-Host "already published: v$($release.version) sequence $($release.sequence)"
        return
    }

    & git -C $temp -c user.name='MNG Cloud' -c user.email='mng-cloud@users.noreply.github.com' `
        commit --quiet -m "Publish signed release $($release.version) sequence $($release.sequence)"
    if ($LASTEXITCODE -ne 0) { throw 'git commit failed' }

    & git -C $temp show --stat --oneline HEAD
    if ($NoPush) {
        Write-Host 'NoPush set; review the branch in:' $temp
        return
    }
    & git -C $temp push --quiet origin "HEAD:$Branch"
    if ($LASTEXITCODE -ne 0) { throw 'git push failed' }
    Write-Host "published v$($release.version) sequence $($release.sequence) to $Repo ($Branch)"
}
finally {
    if ($NoPush -and (Test-Path $temp)) {
        Write-Host "kept $temp for review"
    }
    elseif (Test-Path $temp) {
        Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
    }
}
