# Native Windows fixture checks; no real PATH, service or task changes.
# Run after cmd/release: pwsh -File cmd/installtest/windows.ps1 -ReleaseDir dist
param([string]$Installer = './install.ps1', [string]$ReleaseDir = './dist')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'These fixtures require native Windows.' }
$Installer = (Resolve-Path -LiteralPath $Installer).Path
$ReleaseDir = (Resolve-Path -LiteralPath $ReleaseDir).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('deepai-install-test-' + [Guid]::NewGuid().ToString('N'))
$bin = Join-Path $root "user's bin"
$bundle = Join-Path $root 'release files'
$originalUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$originalProcessPath = $env:PATH
$script:registered = $false
# Read-only OS registration queries are mocked with deterministic fixtures.
function Get-CimInstance { @() }
function Get-ScheduledTask {
    if ($script:registered) {
        [pscustomobject]@{ TaskName='Connect fixture'; Actions=@([pscustomobject]@{
            CimClass=[pscustomobject]@{CimClassName='MSFT_TaskExecAction'}
            Execute=(Join-Path $bin 'deepai-connect.exe')
        }) }
    }
}
function Assert([bool]$condition, [string]$message) { if (!$condition) { throw $message } }
function Invoke-Installer([bool]$Success, [hashtable]$Arguments) {
    $global:LASTEXITCODE = 0
    # Script parameters need named splatting; array strings are positional values.
    $output = & $Installer @Arguments 2>&1 | Out-String
    if (($global:LASTEXITCODE -eq 0) -ne $Success) { throw "Unexpected installer outcome ($global:LASTEXITCODE): $output" }
    return $output
}
try {
    [IO.Directory]::CreateDirectory($bundle) | Out-Null
    Copy-Item -Path (Join-Path $ReleaseDir 'deepai-connect-windows-*.exe') -Destination $bundle
    Copy-Item -LiteralPath (Join-Path $ReleaseDir 'SHA256SUMS') -Destination $bundle
    $argsInstall = @{ FromDir=$bundle; BinDir=$bin; NoPath=$true }
    Invoke-Installer $true $argsInstall | Out-Null
    $dest = Join-Path $bin 'deepai-connect.exe'
    $initial = (Get-FileHash -LiteralPath $dest).Hash
    & $dest version
    Assert ($LASTEXITCODE -eq 0) 'Installed native binary failed.'
    $artifact = if (($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')) { 'deepai-connect-windows-arm64.exe' } else { 'deepai-connect-windows-amd64.exe' }
    $source = Join-Path $bundle $artifact
    # Trailing data gives distinct, checksum-valid fixture bytes without needing a second build.
    $stream = [IO.File]::Open($source, [IO.FileMode]::Append)
    try { $stream.WriteByte(42) } finally { $stream.Dispose() }
    $upgrade = (Get-FileHash -LiteralPath $source).Hash
    $checksum = Join-Path $bundle 'SHA256SUMS'
    [IO.File]::WriteAllText($checksum, "$upgrade  $artifact`n")
    Invoke-Installer $true $argsInstall | Out-Null
    Invoke-Installer $true $argsInstall | Out-Null
    Assert ((Get-FileHash -LiteralPath (Join-Path $bin '.deepai-connect.previous.exe')).Hash -eq $initial) 'Repeat install lost rollback binary.'
    [IO.File]::WriteAllText($checksum, (('0' * 64) + "  $artifact`n"))
    Invoke-Installer $false $argsInstall | Out-Null
    Assert ((Get-FileHash -LiteralPath $dest).Hash -eq $upgrade) 'Checksum failure changed installed CLI.'
    # Emulate interruption after atomic binary replacement, before receipt commit.
    $oldHash = $initial.ToLowerInvariant()
    $newHash = $upgrade.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $bin '.deepai-connect.transaction'), "$oldHash $newHash -`n")
    [IO.File]::WriteAllText((Join-Path $bin '.deepai-connect.sha256'), $oldHash + "`n")
    [IO.File]::WriteAllText((Join-Path $bin '.deepai-connect.previous.sha256'), 'incomplete receipt')
    Invoke-Installer $true @{ Rollback=$true; BinDir=$bin } | Out-Null
    Assert ((Get-FileHash -LiteralPath $dest).Hash -eq $initial) 'Rollback did not restore CLI.'
    $script:registered = $true
    Invoke-Installer $false @{ Uninstall=$true; BinDir=$bin } | Out-Null
    Assert (Test-Path -LiteralPath $dest) 'Removed registered CLI.'
    $script:registered = $false
    (Get-Item -LiteralPath $dest).IsReadOnly = $true
    Invoke-Installer $false @{ Uninstall=$true; BinDir=$bin } | Out-Null
    Assert (Test-Path -LiteralPath $dest) 'Removed read-only CLI.'
    (Get-Item -LiteralPath $dest).IsReadOnly = $false
    $target = Join-Path $root 'junction target'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    $junction = Join-Path $root 'linked bin'
    New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
    Invoke-Installer $false @{ FromDir=$bundle; BinDir=$junction; NoPath=$true } | Out-Null
    Assert (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 0) 'Wrote through a junction.'
    Remove-Item -LiteralPath $junction -Force
    $state = Join-Path $root 'enrolled identity'
    [IO.File]::WriteAllText($state, 'preserve me')
    Invoke-Installer $true @{ Uninstall=$true; BinDir=$bin } | Out-Null
    Invoke-Installer $true @{ Uninstall=$true; BinDir=$bin } | Out-Null
    Assert (!(Test-Path -LiteralPath $dest)) 'Uninstall left CLI.'
    Assert ([IO.File]::ReadAllText($state) -eq 'preserve me') 'Uninstall changed identity.'
    Assert (@(Get-ChildItem -LiteralPath $bin -Force).Count -eq 0) 'Staging/managed artifacts leaked.'
    Assert ([Environment]::GetEnvironmentVariable('Path', 'User') -ceq $originalUserPath) 'Fixture changed real user PATH.'
    Assert ($env:PATH -ceq $originalProcessPath) 'Fixture changed process PATH.'
    Write-Output 'Windows installer native fixtures passed; this does not validate Windows workers.'
    $global:LASTEXITCODE = 0
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
