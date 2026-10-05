<#
.SYNOPSIS
    Applies a text-based .1337 byte patch to a Windows .exe/.dll file.

.DESCRIPTION
    PowerShell port of Win_1337_Apply_Patch v2.4. This is a thin command-line entry point over the
    Win1337Patch module, which holds the shared engine used by both this script and the tests.

    The original v1.0 parameter names (-patchFile / -targetFile / -fixOffset) are preserved for
    backward compatibility, and the v2.4 switches (-fileoffset, -backup, -elevate, -takeownership,
    -schedule) are available alongside them.

    Least-privilege model (parity with v2.4): the script does NOT force administrator rights.
    A protected target only triggers a one-shot UAC child when -elevate is supplied and an eligible
    access denial occurs before any mutation. Ownership fallback (-takeownership) is separate,
    opt-in, target-only, and is attempted only after normal elevated write access fails.

    Exit codes: 0 success, 1 validation/patching/scheduling failure.

.PARAMETER PatchFile
    Path to the .1337 patch file. Aliases: -patchFile, -patch.

.PARAMETER TargetFile
    Path to the target .exe or .dll file.

.PARAMETER FixOffset
    Subtract the 0xC00 file-offset adjustment from every declared offset. Alias: -fileoffset.

.PARAMETER Backup
    Create a uniquely named timestamped .BAK copy of the target before patching.

.PARAMETER Elevate
    Permit one UAC administrator operation when normal access fails before any mutation.

.PARAMETER TakeOwnership
    Authorize target-only takeown/icacls ownership fallback after normal elevated write access fails.
    This does not authorize elevation by itself; also supply -Elevate or run from an administrator
    context.

.PARAMETER Schedule
    Store the patch command in the current user's RunOnce registry key for execution at next login.

.PARAMETER ScheduledRun
    Internal marker added to commands created by the scheduler.

.PARAMETER ElevatedWorker
    Internal one-shot worker marker; it does not grant privileges or bypass validation.

.PARAMETER Help
    Show usage information.

.EXAMPLE
    ./Win_1337_Apply.ps1 -patchFile nvencodeapi64.1337 -targetFile C:\Windows\System32\nvencodeAPI64.dll -backup

.EXAMPLE
    ./Win_1337_Apply.ps1 -patch .\patch.1337 .\target.dll -fileoffset -elevate -takeownership
#>
[CmdletBinding(DefaultParameterSetName = 'Patch')]
param(
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Patch')]
    [Alias('patch')]
    [string]$PatchFile,

    [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Patch')]
    [string]$TargetFile,

    [Alias('fileoffset', 'offset')]
    [switch]$FixOffset,

    [switch]$Backup,

    [switch]$Elevate,

    [switch]$TakeOwnership,

    [switch]$Schedule,

    [switch]$ScheduledRun,

    [switch]$ElevatedWorker,

    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Win1337Log = { param([string]$Message) Write-Host $Message }

function Show-Win1337ScriptUsage {
    param([string]$ErrorMessage)

    if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
        Write-Host "Error: $ErrorMessage" -ForegroundColor Red
    }

    @(
        'Usage:',
        '  Win_1337_Apply.ps1 -patchFile <1337-file> -targetFile <target-file> [options]',
        '',
        'Options:',
        '  -fileoffset           Apply the 0xC00 offset adjustment before patching.',
        '  -backup               Keep a uniquely named timestamped .BAK copy of the target.',
        '  -elevate              Allow one UAC administrator operation only if normal access fails.',
        '  -takeownership        Allow target-only ownership fallback after normal elevated access fails;',
        '                        also requires -elevate or an administrator context.',
        '  -schedule             Schedule the patch for the next login (RunOnce); elevation still',
        '                        requires an explicit -elevate flag and interactive UAC consent.',
        '  -scheduledrun         Internally generated when a scheduled patch executes.',
        '  -elevatedworker       Internal one-shot worker marker; does not authorize elevation.',
        '  -help                 Show this help text.',
        ''
    ) | ForEach-Object { Write-Host $_ }
}

if ($Help) {
    Show-Win1337ScriptUsage
    exit 0
}

$modulePath = Join-Path $PSScriptRoot 'Win1337Patch.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host "Error: engine module not found at '$modulePath'." -ForegroundColor Red
    exit 1
}

Import-Module $modulePath -Force -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($PatchFile) -or [string]::IsNullOrWhiteSpace($TargetFile)) {
    Show-Win1337ScriptUsage 'Both a .1337 patch file (-patchFile) and a target file (-targetFile) are required.'
    exit 1
}

if ($ElevatedWorker -and $Schedule) {
    Show-Win1337ScriptUsage 'An elevated worker cannot schedule patches.'
    exit 1
}

if ($Schedule -and -not $ScheduledRun) {
    $scheduleResult = New-Win1337ScheduledEntry -PatchFilePath $PatchFile -TargetFilePath $TargetFile `
        -FixOffset:$FixOffset.IsPresent -CreateBackup:$Backup.IsPresent -TakeOwnership:$TakeOwnership.IsPresent `
        -Elevate:$Elevate.IsPresent -Log $script:Win1337Log

    if (-not $scheduleResult.Success) {
        Write-Host $scheduleResult.Message -ForegroundColor Red
        exit 1
    }

    Write-Host $scheduleResult.Message
    exit 0
}

$result = Invoke-Win1337ElevatedPatch -PatchFilePath $PatchFile -TargetFilePath $TargetFile `
    -FixOffset:$FixOffset.IsPresent -CreateBackup:$Backup.IsPresent -TakeOwnership:$TakeOwnership.IsPresent `
    -Elevate:$Elevate.IsPresent -ElevatedWorker:$ElevatedWorker.IsPresent `
    -HostExecutable (Get-Process -Id $PID).Path -ScriptPath $PSCommandPath `
    -Log $script:Win1337Log

if ($result.Success) {
    Write-Host $result.Message -ForegroundColor Green
    exit 0
}

Write-Host $result.Message -ForegroundColor Red
exit 1
