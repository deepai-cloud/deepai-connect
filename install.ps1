#requires -Version 5.1
<#
.SYNOPSIS
Install, roll back or remove the current user's DeepAI Connect CLI.
.DESCRIPTION
Uses a SHA256-verified local release or published release, or builds this checkout.
Does not install a VM/driver, enroll a device or change automatic startup.
Windows builds provide SSH administration; Windows workers are not validated.
.EXAMPLE
.\install.ps1 -FromDir . -NoPath
.EXAMPLE
.\install.ps1 -Rollback
.EXAMPLE
.\install.ps1 -Uninstall
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')][string]$FromDir,
    [Parameter(ParameterSetName = 'Install')][switch]$FromSource,
    [Parameter(ParameterSetName = 'Install')][string]$Version,
    [Parameter(ParameterSetName = 'Install')][switch]$NoPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')][switch]$Rollback,
    [Parameter(Mandatory = $true, ParameterSetName = 'Uninstall')][switch]$Uninstall,
    [string]$BinDir = (Join-Path $env:LOCALAPPDATA 'DeepAI Connect\bin')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stage = $null
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This installer requires Windows. Use install.sh on Linux or macOS.' }
    if ($FromSource -and $FromDir) { throw 'Choose only one installation source.' }
    if ($Version -and $Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$') { throw 'Invalid version.' }
    $BinDir = [IO.Path]::GetFullPath($BinDir).TrimEnd('\', '/')
    if ($BinDir -notmatch '^[A-Za-z]:\\.+' -or $BinDir -match '[;\r\n\x00]') {
        throw 'Install directory must be a local absolute directory below a drive root, without semicolons or line breaks.'
    }
    function Assert-SafePath([string]$Path) {
        $current = $Path
        while ($current) {
            if (Test-Path -LiteralPath $current) {
                $item = Get-Item -LiteralPath $current -Force
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $current" }
            }
            $parent = [IO.Path]::GetDirectoryName($current)
            if ($parent -eq $current) { break }
            $current = $parent
        }
    }
    function Get-Digest([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
    function Assert-Managed([string]$Path, [string]$Receipt) {
        if (!(Test-Path -LiteralPath $Path -PathType Leaf) -or !(Test-Path -LiteralPath $Receipt -PathType Leaf)) {
            throw 'No managed CLI or backup found; install a verified bundle first.'
        }
        if ((Get-Digest $Path) -ne ([IO.File]::ReadAllText($Receipt).Trim())) {
            throw 'Managed CLI or backup was changed; refusing to remove or replace it.'
        }
    }
    $destination = Join-Path $BinDir 'deepai-connect.exe'
    $receipt = Join-Path $BinDir '.deepai-connect.sha256'
    $previous = Join-Path $BinDir '.deepai-connect.previous.exe'
    $previousReceipt = Join-Path $BinDir '.deepai-connect.previous.sha256'
    $transaction = Join-Path $BinDir '.deepai-connect.transaction'
    foreach ($path in @($destination, $receipt, $previous, $previousReceipt, $transaction)) {
        Assert-SafePath $path
        if (Test-Path -LiteralPath $path) {
            if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Refusing non-file: $path" }
            if ((Get-Item -LiteralPath $path -Force).IsReadOnly) { throw "Refusing read-only file: $path" }
        }
    }
    # Recover only bytes matching the durable transaction hashes. This handles
    # interruption between an atomic executable replacement and receipt writes.
    if (Test-Path -LiteralPath $transaction) {
        $fields = [IO.File]::ReadAllText($transaction).Trim() -split ' '
        if ($fields.Count -ne 3 -or $fields[0] -notmatch '^(-|[a-f0-9]{64})$' -or $fields[1] -notmatch '^[a-f0-9]{64}$' -or $fields[2] -notmatch '^(-|[a-f0-9]{64})$') {
            throw 'Invalid installer transaction; preserve it for inspection.'
        }
        $currentDigest = '-'
        $backupDigest = '-'
        if (Test-Path -LiteralPath $destination) { $currentDigest = Get-Digest $destination }
        if (Test-Path -LiteralPath $previous) { $backupDigest = Get-Digest $previous }
        if ($currentDigest -ne $fields[0] -and $currentDigest -ne $fields[1]) { throw 'Interrupted installation binary changed; preserve transaction and inspect manually.' }
        if ($backupDigest -ne $fields[0] -and $backupDigest -ne $fields[2]) { throw 'Interrupted installation backup changed; preserve transaction and inspect manually.' }
        if ($currentDigest -eq $fields[1] -and $fields[0] -ne '-' -and $fields[0] -ne $fields[1] -and $backupDigest -ne $fields[0]) { throw 'Interrupted installation lost its rollback binary; preserve transaction and inspect manually.' }
        if ($currentDigest -ne '-') { [IO.File]::WriteAllText($receipt, $currentDigest + "`n") }
        if ($backupDigest -ne '-') { [IO.File]::WriteAllText($previousReceipt, $backupDigest + "`n") }
        Remove-Item -LiteralPath $transaction -Force
    }
    if ($Uninstall) {
        # Removal is CLI-only. Refuse registered services/tasks rather than silently
        # breaking startup or changing another component's lifecycle.
        foreach ($service in @(Get-CimInstance Win32_Service)) {
            if ($service.PathName -and $service.PathName.IndexOf($destination, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "CLI is referenced by service $($service.Name); remove its registration before uninstalling."
            }
        }
        foreach ($task in @(Get-ScheduledTask)) {
            foreach ($action in @($task.Actions)) {
                if ($action.CimClass.CimClassName -eq 'MSFT_TaskExecAction' -and $action.Execute -and $action.Execute.Trim('"') -ieq $destination) {
                    throw "CLI is referenced by scheduled task $($task.TaskName); disable/remove its Connect startup registration first."
                }
            }
        }
        if (!(Test-Path -LiteralPath $destination) -and !(Test-Path -LiteralPath $receipt) -and !(Test-Path -LiteralPath $previous) -and !(Test-Path -LiteralPath $previousReceipt)) {
            Write-Output 'CLI is already uninstalled. Configuration, identities and PATH retained.'
            return
        }
        Assert-Managed $destination $receipt
        if ((Test-Path -LiteralPath $previous) -or (Test-Path -LiteralPath $previousReceipt)) { Assert-Managed $previous $previousReceipt }
        foreach ($path in @($destination, $receipt, $previous, $previousReceipt, $transaction)) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        Write-Output 'Removed managed CLI. Configuration, enrolled identities and user PATH entries retained.'
        return
    }
    if ((Test-Path -LiteralPath $previous) -or (Test-Path -LiteralPath $previousReceipt)) { Assert-Managed $previous $previousReceipt }
    if ($Rollback) {
        Assert-Managed $destination $receipt
        Assert-Managed $previous $previousReceipt
    }
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    switch ($arch) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw 'Supported Windows architectures are amd64 and arm64.' }
    }
    $asset = "deepai-connect-windows-$arch.exe"
    [IO.Directory]::CreateDirectory($BinDir) | Out-Null
    $stage = Join-Path $BinDir ('.deepai-connect-install.' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $candidate = Join-Path $stage $asset
    if ($Rollback) {
        Copy-Item -LiteralPath $previous -Destination $candidate
    } elseif ($FromSource) {
        if (!(Get-Command go -ErrorAction SilentlyContinue)) { throw '-FromSource requires Go; use -FromDir with a release bundle otherwise.' }
        if (!(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'go.mod'))) { throw '-FromSource must run from a project checkout.' }
        if (!$Version) { $Version = 'dev' }
        $names = @('GOTOOLCHAIN', 'GOWORK', 'CGO_ENABLED', 'GOOS', 'GOARCH', 'GOAMD64', 'GOARM64', 'GOFLAGS', 'GOEXPERIMENT')
        $saved = @{}
        foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
        try {
            foreach ($entry in @{GOTOOLCHAIN='auto';GOWORK='off';CGO_ENABLED='0';GOOS='windows';GOARCH=$arch;GOAMD64='v1';GOARM64='v8.0';GOFLAGS='';GOEXPERIMENT=''}.GetEnumerator()) {
                [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
            }
            Push-Location -LiteralPath $PSScriptRoot
            try {
                & go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/deepai-cloud/deepai-connect/internal/buildinfo.Version=$Version" -o $candidate ./cmd/deepai-connect
                if ($LASTEXITCODE -ne 0) { throw 'Source build failed; previous installation is unchanged.' }
            } finally { Pop-Location }
        } finally {
            foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
        }
    } else {
        if (!$FromDir -and !$Version -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS'))) { $FromDir = $PSScriptRoot }
        $sumPath = Join-Path $stage 'SHA256SUMS'
        if ($FromDir) {
            Copy-Item -LiteralPath (Join-Path $FromDir $asset) -Destination $candidate
            Copy-Item -LiteralPath (Join-Path $FromDir 'SHA256SUMS') -Destination $sumPath
        } else {
            if (!$Version -or $Version -eq 'latest') { $base = 'https://github.com/deepai-cloud/deepai-connect/releases/latest/download' }
            else { $base = "https://github.com/deepai-cloud/deepai-connect/releases/download/$Version" }
            # curl.exe enforces HTTPS both initially and across redirects.
            if (!(Get-Command curl.exe -ErrorAction SilentlyContinue)) { throw 'curl.exe is required for downloads; use -FromDir with a local verified release.' }
            foreach ($name in @('SHA256SUMS', $asset)) {
                & curl.exe --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --output (Join-Path $stage $name) "$base/$name"
                if ($LASTEXITCODE -ne 0) { throw "Could not download $name; use -FromSource or -FromDir if that release does not publish windows/$arch." }
            }
        }
        $entries = @(Get-Content -LiteralPath $sumPath | Where-Object { $_ -match ('^[0-9a-fA-F]{64}\s+' + [regex]::Escape($asset) + '$') })
        $matchingNames = @(Get-Content -LiteralPath $sumPath | Where-Object { ($_ -split '\s+', 2)[-1] -eq $asset })
        if ($entries.Count -ne 1 -or $matchingNames.Count -ne 1) { throw "SHA256SUMS must contain exactly one valid checksum for $asset." }
        $expected = ($entries[0] -split '\s+', 2)[0]
        if ((Get-Digest $candidate) -ne $expected) { throw 'Checksum mismatch; previous installation is unchanged.' }
    }
    foreach ($path in @($destination, $receipt, $previous, $previousReceipt, $transaction)) { Assert-SafePath $path }
    $newDigest = Get-Digest $candidate
    $oldDigest = '-'
    $backupDigest = '-'
    if (Test-Path -LiteralPath $destination) { $oldDigest = Get-Digest $destination }
    if (Test-Path -LiteralPath $previous) { $backupDigest = Get-Digest $previous }
    $stagedTransaction = Join-Path $stage 'transaction'
    [IO.File]::WriteAllText($stagedTransaction, "$oldDigest $newDigest $backupDigest`n")
    [IO.File]::Move($stagedTransaction, $transaction)
    if (Test-Path -LiteralPath $destination) {
        if ((Get-Digest $destination) -ne $newDigest) {
            # Same-volume atomic replacement also retains the previous executable.
            [IO.File]::Replace($candidate, $destination, $previous)
            [IO.File]::WriteAllText($previousReceipt, (Get-Digest $previous) + "`n")
        }
    } else { [IO.File]::Move($candidate, $destination) }
    [IO.File]::WriteAllText($receipt, $newDigest + "`n")
    Remove-Item -LiteralPath $transaction -Force
    Write-Output "Installed $destination"
    Write-Output 'CLI only: no service, login task, VM, mesh or startup preference was changed.'
    if ($Rollback) { return }
    if (!$NoPath) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (@($userPath -split ';') -inotcontains $BinDir) {
            $newPath = $BinDir
            if ($userPath) { $newPath += ';' + $userPath }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Output 'Added user PATH. Open a new terminal to use deepai-connect.'
        }
    }
    Write-Output 'Next: deepai-connect setup --hub USER@HOST'
    Write-Output 'Then: deepai-connect status'
    Write-Output 'Windows worker runtime is not validated; installing this CLI does not establish worker support.'
} catch {
    Write-Error "deepai-connect installer: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
