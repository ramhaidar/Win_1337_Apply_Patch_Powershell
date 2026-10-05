#Requires -Version 7.0

<#
.SYNOPSIS
    Core engine for applying text-based .1337 byte patches to Windows .exe/.dll files.

.DESCRIPTION
    This module is the single source of truth for the PowerShell port of Win_1337_Apply_Patch.
    It mirrors the behavior of the C# reference (v2.4) engine:

    * Validates the `>filename` header and that the declared target filename matches the real target.
    * Parses `offset:expected->replacement` hexadecimal entries; `-FixOffset` subtracts 0xC00.
    * Validates expected bytes on a read pass and re-validates them on the exclusive writable stream
      before any mutation, so a changed target is never overwritten blindly.
    * Creates a uniquely named timestamped backup only when requested and only after validation.
    * Removes the PE certificate and recalculates the PE checksum after a successful write.
    * Returns a PatchOutcome object instead of throwing for expected failures.

    Privilege handling follows the reference least-privilege model: no forced elevation, an explicit
    one-shot elevated child only on a pre-mutation access denial, and an opt-in, target-only
    takeown/icacls ownership fallback that is attempted only after normal elevated access fails.

    The `-SkipChecksum` parameter of the private core function is the PowerShell equivalent of the
    reference's `internal` test-only path. It is intentionally NOT part of the exported surface, so
    production callers can never skip PE normalization; tests reach it through InModuleScope.
#>

Set-StrictMode -Version 3.0

$script:FileOffsetAdjustment = 0xC00
$script:RunOnceKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$script:NativeTypesReady = $false

#region Native types and PE helpers

function Initialize-Win1337NativeTypes {
    [CmdletBinding()]
    param()

    if ($script:NativeTypesReady) {
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

namespace Win1337
{
    public static class ImageHlp
    {
        [DllImport("Imagehlp.dll", EntryPoint = "MapFileAndCheckSum", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint MapFileAndCheckSum(string filename, out uint headerSum, out uint checkSum);

        [DllImport("Imagehlp.dll", EntryPoint = "ImageRemoveCertificate", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImageRemoveCertificate(IntPtr handle, int index);
    }
}
'@

    Add-Type -TypeDefinition $source -ErrorAction Stop
    $script:NativeTypesReady = $true
}

function Get-Win1337PeChecksum {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.File]::Exists($fullPath)) {
        return $null
    }

    Initialize-Win1337NativeTypes
    [uint32]$headerSum = 0
    [uint32]$calculatedSum = 0
    $returnCode = [Win1337.ImageHlp]::MapFileAndCheckSum($fullPath, [ref]$headerSum, [ref]$calculatedSum)
    if ($returnCode -ne 0) {
        return $null
    }

    return @{ HeaderSum = $headerSum; CheckSum = $calculatedSum }
}

function Set-Win1337PeChecksum {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.File]::Exists($fullPath)) {
        return $false
    }

    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if ($bytes.Length -lt 0x40) {
        return $false
    }

    # IMAGE_DOS_HEADER: e_magic at 0x00, e_lfanew at 0x3C.
    if ([System.BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) {
        return $false
    }

    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 4) -gt $bytes.Length) {
        return $false
    }

    # IMAGE_NT_HEADERS signature "PE\0\0".
    if ([System.BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
        return $false
    }

    # IMAGE_OPTIONAL_HEADER.CheckSum = PE offset + 4 (signature) + 20 (file header) + 64.
    $checksumOffset = $peOffset + 4 + 20 + 64
    if (($checksumOffset + 4) -gt $bytes.Length) {
        return $false
    }

    $checksum = Get-Win1337PeChecksum -Path $fullPath
    if ($null -eq $checksum) {
        return $false
    }

    $checksumBytes = [System.BitConverter]::GetBytes([uint32]$checksum.CheckSum)
    [System.Array]::Copy($checksumBytes, 0, $bytes, $checksumOffset, 4)
    [System.IO.File]::WriteAllBytes($fullPath, $bytes)
    return $true
}

function Remove-Win1337PeCertificate {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    Initialize-Win1337NativeTypes

    $stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $handle = $stream.SafeFileHandle.DangerousGetHandle()
        return [Win1337.ImageHlp]::ImageRemoveCertificate($handle, 0)
    } finally {
        $stream.Dispose()
    }
}

function Invoke-Win1337Normalize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [scriptblock]$Log
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    Write-Win1337Log -Log $Log -Message "Removing PE certificate from '$fullPath'."
    [void](Remove-Win1337PeCertificate -Path $fullPath)

    Write-Win1337Log -Log $Log -Message "Recalculating PE checksum for '$fullPath'."
    if (-not (Set-Win1337PeChecksum -Path $fullPath)) {
        throw [System.IO.IOException]::new('Checksum recalculation failed.')
    }
    Write-Win1337Log -Log $Log -Message 'PE checksum normalized.'
}

#endregion

#region Outcome helpers

function New-Win1337Success {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$BackupPath
    )

    return [pscustomobject]@{
        PSTypeName          = 'Win1337.PatchOutcome'
        Success             = $true
        Message             = $Message
        BackupPath          = $BackupPath
        Error               = $null
        FailureKind         = 'None'
        Stage               = 'None'
        TargetMayBeModified = $false
        CanRetryElevated    = $false
    }
}

function New-Win1337Failure {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('None', 'Validation', 'AccessDenied', 'IoFailure', 'PostMutationFailure', 'PrivilegedOperationFailed')]
        [string]$FailureKind = 'Validation',

        [ValidateSet('None', 'PatchRead', 'TargetRead', 'TargetWrite', 'Backup', 'Ownership', 'Normalize')]
        [string]$Stage = 'None',

        [bool]$TargetMayBeModified = $false,

        [string]$BackupPath,

        [System.Exception]$FailureException
    )

    $canRetryElevated = ($FailureKind -eq 'AccessDenied') -and (-not $TargetMayBeModified) -and
    ($Stage -in @('TargetRead', 'TargetWrite', 'Backup'))

    return [pscustomobject]@{
        PSTypeName          = 'Win1337.PatchOutcome'
        Success             = $false
        Message             = $Message
        BackupPath          = $BackupPath
        Error               = $FailureException
        FailureKind         = $FailureKind
        Stage               = $Stage
        TargetMayBeModified = $TargetMayBeModified
        CanRetryElevated    = $canRetryElevated
    }
}

#endregion

#region Shared helpers

function Write-Win1337Log {
    [CmdletBinding()]
    param(
        [scriptblock]$Log,

        [string]$Message
    )

    if ($null -ne $Log) {
        & $Log $Message
    }
}

function Test-Win1337Admin {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
}

function Get-Win1337SystemDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess) {
        return [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Windows'), 'Sysnative')
    }

    return [System.Environment]::SystemDirectory
}

function ConvertTo-Win1337QuotedArgument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $quoted = [System.Text.StringBuilder]::new('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }

        if ($character -eq '"') {
            [void]$quoted.Append('\', ($backslashes * 2) + 1)
        } else {
            [void]$quoted.Append('\', $backslashes)
        }

        [void]$quoted.Append($character)
        $backslashes = 0
    }

    [void]$quoted.Append('\', $backslashes * 2)
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-Win1337Process {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList,

        [scriptblock]$Log
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw [System.IO.IOException]::new("Could not start process '$FilePath'.")
    }

    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()

        if (-not [string]::IsNullOrWhiteSpace($stdout)) {
            Write-Win1337Log -Log $Log -Message $stdout.Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            Write-Win1337Log -Log $Log -Message $stderr.Trim()
        }

        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

#endregion

#region Target resolution

function Resolve-Win1337PatchTarget {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [string]$WindowsDirectory = $env:WINDIR
    )

    if ([string]::IsNullOrWhiteSpace($PatchFilePath)) {
        return $null
    }

    $patchFileName = [System.IO.Path]::GetFileName($PatchFilePath)
    if ([string]::IsNullOrWhiteSpace($patchFileName) -or [string]::IsNullOrWhiteSpace($WindowsDirectory)) {
        return $null
    }

    switch ($patchFileName.ToLowerInvariant()) {
        'nvencodeapi.1337' {
            return [System.IO.Path]::Combine($WindowsDirectory, 'SysWOW64', 'nvEncodeAPI.dll')
        }
        'nvencodeapi64.1337' {
            return [System.IO.Path]::Combine($WindowsDirectory, 'System32', 'nvEncodeAPI64.dll')
        }
        default {
            return $null
        }
    }
}

#endregion

#region Patch parsing and validation

function Get-Win1337PatchEntry {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[psobject]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines,

        [bool]$FixOffset = $false
    )

    if ($Lines.Length -eq 0) {
        return $null
    }

    $header = $Lines[0].Trim()
    if (-not $header.StartsWith('>')) {
        return $null
    }

    $expectedName = $header.Substring(1).Trim()
    if ([string]::IsNullOrWhiteSpace($expectedName)) {
        return $null
    }

    $entries = [System.Collections.Generic.List[psobject]]::new()
    $adjustment = if ($FixOffset) { $script:FileOffsetAdjustment } else { 0 }

    for ($index = 1; $index -lt $Lines.Length; $index++) {
        $line = $Lines[$index].Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        $colonIndex = $line.IndexOf(':')
        if ($colonIndex -le 0 -or $colonIndex -eq ($line.Length - 1)) {
            return $null
        }

        $offsetText = $line.Substring(0, $colonIndex).Trim()
        $remainder = $line.Substring($colonIndex + 1)
        $tokens = $remainder.Replace('->', ':').Split(':')
        if ($tokens.Length -lt 2) {
            return $null
        }

        [int]$offset = 0
        if (-not [int]::TryParse($offsetText, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$offset)) {
            return $null
        }

        [long]$adjustedOffset = [long]$offset - $adjustment
        if ($adjustedOffset -lt 0 -or $adjustedOffset -gt [int]::MaxValue) {
            return $null
        }

        [byte]$expectedByte = 0
        if (-not [byte]::TryParse($tokens[0], [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$expectedByte)) {
            return $null
        }

        [byte]$replacementByte = 0
        if (-not [byte]::TryParse($tokens[1], [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$replacementByte)) {
            return $null
        }

        $entries.Add([pscustomobject]@{
                PSTypeName = 'Win1337.PatchEntry'
                Offset     = [int]$adjustedOffset
                Expected   = $expectedByte
                Replacement = $replacementByte
                Line       = $index + 1
            })
    }

    # Unary comma keeps the list intact; without it the pipeline would enumerate
    # the collection into an Object[] and any later [List] binding would copy it.
    return , $entries
}

function Test-Win1337AndReplace {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[psobject]]$Entries
    )

    foreach ($entry in $Entries) {
        if ($entry.Offset -ge $Buffer.Length) {
            return New-Win1337Failure -Message ("Line {0}: computed offset 0x{1:X} is outside the target file." -f $entry.Line, $entry.Offset)
        }

        if ($Buffer[$entry.Offset] -ne $entry.Expected) {
            return New-Win1337Failure -Message ("Offset 0x{0:X} mismatch: found 0x{1:X2}, expected 0x{2:X2}." -f $entry.Offset, $Buffer[$entry.Offset], $entry.Expected)
        }
    }

    foreach ($entry in $Entries) {
        $Buffer[$entry.Offset] = $entry.Replacement
    }

    return $null
}

#endregion

#region Backup

function New-Win1337Backup {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [scriptblock]$Log
    )

    $backupPath = '{0}.{1:yyyy-MM-dd_hh-mm-ss-tt}.{2}.BAK' -f $TargetPath, [datetime]::Now, [guid]::NewGuid().ToString('N')
    $stream = [System.IO.File]::Open($backupPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush()
    } finally {
        $stream.Dispose()
    }

    Write-Win1337Log -Log $Log -Message "Backup created at '$backupPath'."
    return $backupPath
}

#endregion

#region Ownership fallback

function Invoke-Win1337OwnershipFallback {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [scriptblock]$Log
    )

    $systemDirectory = Get-Win1337SystemDirectory
    $takeownPath = [System.IO.Path]::Combine($systemDirectory, 'takeown.exe')
    $icaclsPath = [System.IO.Path]::Combine($systemDirectory, 'icacls.exe')

    try {
        Write-Win1337Log -Log $Log -Message "Requesting ownership of '$TargetPath'."
        $takeownExit = Invoke-Win1337Process -FilePath $takeownPath -ArgumentList @('/F', $TargetPath) -Log $Log
        if ($takeownExit -ne 0) {
            $takeownMessage = "takeown failed (exit $takeownExit); ownership may have changed. Patching stopped."
            return New-Win1337Failure -Message $takeownMessage `
                -FailureKind PrivilegedOperationFailed -Stage Ownership
        }

        $icaclsExit = Invoke-Win1337Process -FilePath $icaclsPath -ArgumentList @($TargetPath, '/grant', '*S-1-5-32-544:F') -Log $Log
        if ($icaclsExit -ne 0) {
            $icaclsMessage = "icacls failed (exit $icaclsExit); ownership may have changed but access was not granted. Patching stopped."
            return New-Win1337Failure -Message $icaclsMessage `
                -FailureKind PrivilegedOperationFailed -Stage Ownership
        }

        Write-Win1337Log -Log $Log -Message "Ownership and administrator access updated for '$TargetPath'."
        return New-Win1337Success -Message 'Ownership fallback completed.'
    } catch {
        $ownershipMessage = "Ownership fallback failed: $($_.Exception.Message). Ownership may have changed. Patching stopped."
        return New-Win1337Failure -Message $ownershipMessage `
            -FailureKind PrivilegedOperationFailed -Stage Ownership -FailureException $_.Exception
    }
}

#endregion

#region Scheduling

function Get-Win1337ScheduledCommandLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExecutablePath,

        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath,

        [bool]$FixOffset = $false,
        [bool]$CreateBackup = $false,
        [bool]$TakeOwnership = $false,
        [bool]$Elevate = $false
    )

    $parts = @(
        (ConvertTo-Win1337QuotedArgument -Value $ExecutablePath),
        '-patch',
        (ConvertTo-Win1337QuotedArgument -Value $PatchFilePath),
        (ConvertTo-Win1337QuotedArgument -Value $TargetFilePath)
    )

    if ($FixOffset) { $parts += '-fileoffset' }
    if ($CreateBackup) { $parts += '-backup' }
    if ($TakeOwnership) { $parts += '-takeownership' }
    if ($Elevate) { $parts += '-elevate' }
    $parts += '-scheduledrun'

    return ($parts -join ' ')
}

function New-Win1337ScheduledEntry {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath,

        [bool]$FixOffset = $false,
        [bool]$CreateBackup = $false,
        [bool]$TakeOwnership = $false,
        [bool]$Elevate = $false,

        [string]$ExecutablePath = (Get-Process -Id $PID).Path,

        [scriptblock]$Log
    )

    $patchPath = [System.IO.Path]::GetFullPath($PatchFilePath)
    $targetPath = [System.IO.Path]::GetFullPath($TargetFilePath)

    if (-not [System.IO.File]::Exists($patchPath)) {
        return New-Win1337Failure -Message "Patch file not found: $patchPath"
    }
    if (-not [System.IO.File]::Exists($targetPath)) {
        return New-Win1337Failure -Message "Target file not found: $targetPath"
    }

    $commandLine = Get-Win1337ScheduledCommandLine -ExecutablePath $ExecutablePath -PatchFilePath $patchPath `
        -TargetFilePath $targetPath -FixOffset $FixOffset -CreateBackup $CreateBackup -TakeOwnership $TakeOwnership -Elevate $Elevate

    try {
        $entryName = 'Win_1337_Patch_{0:yyyyMMddHHmmss}_{1}' -f [datetime]::UtcNow, [guid]::NewGuid().ToString('N')
        $runOnceKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:RunOnceKeyPath, $true)
        if ($null -eq $runOnceKey) {
            $runOnceKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:RunOnceKeyPath)
        }
        if ($null -eq $runOnceKey) {
            return New-Win1337Failure -Message 'Could not access the RunOnce registry key.'
        }

        try {
            $runOnceKey.SetValue($entryName, $commandLine, [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $runOnceKey.Dispose()
        }

        Write-Win1337Log -Log $Log -Message "Scheduled run-once entry '$entryName'."
        Write-Win1337Log -Log $Log -Message "RunOnce command: $commandLine"

        return New-Win1337Success -Message "Patch scheduled for next login (entry '$entryName'). UAC consent is still required if elevation was requested and access requires it."
    } catch {
        return New-Win1337Failure -Message "Failed to schedule patch: $($_.Exception.Message)" -FailureException $_.Exception
    }
}

#endregion

#region Elevation

function Get-Win1337ElevatedArguments {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath,

        [bool]$FixOffset = $false,
        [bool]$CreateBackup = $false,
        [bool]$TakeOwnership = $false
    )

    $parts = @(
        '-patch',
        (ConvertTo-Win1337QuotedArgument -Value $PatchFilePath),
        (ConvertTo-Win1337QuotedArgument -Value $TargetFilePath)
    )

    if ($FixOffset) { $parts += '-fileoffset' }
    if ($CreateBackup) { $parts += '-backup' }
    if ($TakeOwnership) { $parts += '-takeownership' }
    $parts += '-elevatedworker'

    return ($parts -join ' ')
}

function Invoke-Win1337ElevatedLaunch {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostExecutable,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$Arguments,

        [scriptblock]$Log
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $HostExecutable
    $startInfo.Arguments = '-NoProfile -File ' + (ConvertTo-Win1337QuotedArgument -Value $ScriptPath) + ' ' + $Arguments
    $startInfo.UseShellExecute = $true
    $startInfo.Verb = 'runas'

    Write-Win1337Log -Log $Log -Message "Launching elevated worker: $HostExecutable $($startInfo.Arguments)"

    try {
        $process = [System.Diagnostics.Process]::Start($startInfo)
        if ($null -eq $process) {
            return New-Win1337Failure -Message 'Could not start the elevated patch process.'
        }

        try {
            $process.WaitForExit()
            if ($process.ExitCode -eq 0) {
                return New-Win1337Success -Message 'Elevated patch operation completed successfully. See the child console for details and backup location.'
            }

            $failedMessage = "Elevated patch operation failed (exit $($process.ExitCode))." +
            ' See the child console for details; inspect the target before retrying.'
            return New-Win1337Failure -Message $failedMessage `
                -FailureKind PostMutationFailure -Stage TargetWrite -TargetMayBeModified $true
        } finally {
            $process.Dispose()
        }
    } catch [System.ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -eq 1223) {
            return New-Win1337Failure -Message 'Administrator operation cancelled by UAC. The elevated patch was not started.' `
                -FailureKind AccessDenied -Stage TargetWrite
        }

        $win32Message = "Could not complete the elevated operation: $($_.Exception.Message)." +
        ' Inspect the target before retrying if a child process started.'
        return New-Win1337Failure -Message $win32Message `
            -FailureKind IoFailure -Stage TargetWrite -TargetMayBeModified $true
    } catch {
        $errorMessage = "Could not complete the elevated operation: $($_.Exception.Message)." +
        ' Inspect the target before retrying if a child process started.'
        return New-Win1337Failure -Message $errorMessage `
            -FailureKind IoFailure -Stage TargetWrite -TargetMayBeModified $true
    }
}

#endregion

#region Engine core

function Invoke-Win1337Core {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath,

        [bool]$FixOffset = $false,
        [bool]$CreateBackup = $false,
        [bool]$TakeOwnership = $false,
        [bool]$SkipChecksum = $false,

        [scriptblock]$Log
    )

    $stage = 'None'
    $backupPath = $null
    $mutationStarted = $false

    try {
        Write-Win1337Log -Log $Log -Message 'Starting patch engine...'

        $patchPath = [System.IO.Path]::GetFullPath($PatchFilePath)
        $targetPath = [System.IO.Path]::GetFullPath($TargetFilePath)
        Write-Win1337Log -Log $Log -Message "Patch definition: $patchPath"
        Write-Win1337Log -Log $Log -Message "Target file: $targetPath"

        if (-not [System.IO.File]::Exists($patchPath)) {
            return New-Win1337Failure -Message "Patch file not found: $patchPath"
        }
        if (-not [System.IO.File]::Exists($targetPath)) {
            return New-Win1337Failure -Message "Target file not found: $targetPath"
        }

        $stage = 'PatchRead'
        $lines = [System.IO.File]::ReadAllLines($patchPath)
        if ($lines.Length -eq 0) {
            return New-Win1337Failure -Message 'Patch file is empty.'
        }

        $header = $lines[0].Trim()
        if (-not $header.StartsWith('>')) {
            return New-Win1337Failure -Message 'Patch file does not start with a valid header.'
        }

        $expectedName = $header.Substring(1).Trim()
        if ([string]::IsNullOrWhiteSpace($expectedName)) {
            return New-Win1337Failure -Message 'Patch header does not contain a target filename.'
        }

        $expectedFileName = [System.IO.Path]::GetFileName($expectedName)
        $actualFileName = [System.IO.Path]::GetFileName($targetPath)
        if (-not [string]::Equals($expectedFileName, $actualFileName, [System.StringComparison]::OrdinalIgnoreCase)) {
            return New-Win1337Failure -Message "The .1337 file is not valid for '$actualFileName'. Expected '$expectedFileName'."
        }

        $entries = Get-Win1337PatchEntry -Lines $lines -FixOffset $FixOffset
        if ($null -eq $entries) {
            return New-Win1337Failure -Message 'Patch file contains an invalid entry.'
        }

        # Read-only validation pass.
        $stage = 'TargetRead'
        $readStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        try {
            $validation = Test-Win1337AndReplace -Buffer (Read-Win1337AllBytes -Stream $readStream) -Entries $entries
        } finally {
            $readStream.Dispose()
        }
        if ($null -ne $validation) {
            return $validation
        }

        # Exclusive writable pass; re-validate the current bytes before mutating.
        $stage = 'TargetWrite'
        $writeStream = $null
        try {
            $writeStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        } catch [System.UnauthorizedAccessException] {
            if ($TakeOwnership -and (Test-Win1337Admin)) {
                $stage = 'Ownership'
                $ownership = Invoke-Win1337OwnershipFallback -TargetPath $targetPath -Log $Log
                if (-not $ownership.Success) {
                    return $ownership
                }
                $stage = 'TargetWrite'
                $writeStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            } else {
                throw
            }
        }

        try {
            $buffer = Read-Win1337AllBytes -Stream $writeStream
            # Snapshot the validated on-disk bytes before the in-place replacement so the
            # optional backup always contains the ORIGINAL file, matching the reference.
            $originalBytes = [byte[]]$buffer.Clone()
            $validation = Test-Win1337AndReplace -Buffer $buffer -Entries $entries
            if ($null -ne $validation) {
                return $validation
            }

            if ($CreateBackup) {
                $stage = 'Backup'
                $backupPath = New-Win1337Backup -TargetPath $targetPath -Bytes $originalBytes -Log $Log
            }

            $stage = 'TargetWrite'
            $writeStream.Position = 0
            $mutationStarted = $true
            $writeStream.Write($buffer, 0, $buffer.Length)
            $writeStream.Flush()
            Write-Win1337Log -Log $Log -Message "Wrote $($buffer.Length) bytes to '$targetPath'."
        } finally {
            $writeStream.Dispose()
        }

        if (-not $SkipChecksum) {
            $stage = 'Normalize'
            Invoke-Win1337Normalize -Path $targetPath -Log $Log
        } else {
            Write-Win1337Log -Log $Log -Message 'Checksum normalization skipped.'
        }

        $successMessage = "File $([System.IO.Path]::GetFileName($targetPath)) patched successfully."
        if (-not [string]::IsNullOrEmpty($backupPath)) {
            $successMessage += " Backup saved to $backupPath."
        }

        return New-Win1337Success -Message $successMessage -BackupPath $backupPath
    } catch {
        $kind = if ($mutationStarted) { 'PostMutationFailure' }
        elseif ($_.Exception -is [System.UnauthorizedAccessException]) { 'AccessDenied' }
        else { 'IoFailure' }
        $message = "Patch failed during $stage`: $($_.Exception.Message)"
        if ($mutationStarted) {
            $message += ' The target may have changed; do not retry without inspecting or restoring it.'
        }
        if (-not [string]::IsNullOrEmpty($backupPath)) {
            $message += " Backup saved to $backupPath."
        }
        return New-Win1337Failure -Message $message -FailureKind $kind -Stage $stage -TargetMayBeModified $mutationStarted -BackupPath $backupPath -FailureException $_.Exception
    }
}

function Read-Win1337AllBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream
    )

    $length = [int]$Stream.Length
    $buffer = [byte[]]::new($length)
    $Stream.Position = 0
    $read = 0
    while ($read -lt $length) {
        $count = $Stream.Read($buffer, $read, $length - $read)
        if ($count -le 0) {
            break
        }
        $read += $count
    }

    # Unary comma prevents pipeline enumeration so callers receive the SAME byte[]
    # instance; Test-Win1337AndReplace mutates the buffer in place before it is written.
    return , $buffer
}

#endregion

#region Public surface

function Invoke-Win1337Patch {
    <#
    .SYNOPSIS
        Applies a .1337 patch to a target .exe/.dll using the default Windows execution context.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$TargetFilePath,

        [switch]$FixOffset,
        [switch]$CreateBackup,
        [switch]$TakeOwnership,

        [scriptblock]$Log
    )

    return Invoke-Win1337Core -PatchFilePath $PatchFilePath -TargetFilePath $TargetFilePath `
        -FixOffset:$FixOffset.IsPresent -CreateBackup:$CreateBackup.IsPresent `
        -TakeOwnership:$TakeOwnership.IsPresent -SkipChecksum:$false -Log $Log
}

function Invoke-Win1337ElevatedPatch {
    <#
    .SYNOPSIS
        Applies a patch, and when an eligible pre-mutation access denial occurs and -Elevate was
        requested, retries once through an explicitly authorized elevated child process.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PatchFilePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetFilePath,

        [switch]$FixOffset,
        [switch]$CreateBackup,
        [switch]$TakeOwnership,
        [switch]$Elevate,
        [switch]$ElevatedWorker,

        [string]$HostExecutable = (Get-Process -Id $PID).Path,
        [string]$ScriptPath,

        [scriptblock]$Log
    )

    $result = Invoke-Win1337Patch -PatchFilePath $PatchFilePath -TargetFilePath $TargetFilePath `
        -FixOffset:$FixOffset.IsPresent -CreateBackup:$CreateBackup.IsPresent `
        -TakeOwnership:$TakeOwnership.IsPresent -Log $Log

    if ($result.Success -or (-not $result.CanRetryElevated) -or $ElevatedWorker -or (Test-Win1337Admin)) {
        return $result
    }

    if (-not $Elevate) {
        $elevateMessage = $result.Message +
        ' Use -elevate to request administrator access, or run from an administrator context.'
        return New-Win1337Failure -Message $elevateMessage -FailureKind $result.FailureKind -Stage $result.Stage
    }

    if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
        $pathMessage = 'Elevation was requested but the script path is unknown;' +
        ' run the patch again from the script entry point.'
        return New-Win1337Failure -Message $pathMessage -FailureKind $result.FailureKind -Stage $result.Stage
    }

    $arguments = Get-Win1337ElevatedArguments -PatchFilePath $PatchFilePath -TargetFilePath $TargetFilePath `
        -FixOffset:$FixOffset.IsPresent -CreateBackup:$CreateBackup.IsPresent -TakeOwnership:$TakeOwnership.IsPresent

    return Invoke-Win1337ElevatedLaunch -HostExecutable $HostExecutable -ScriptPath $ScriptPath -Arguments $arguments -Log $Log
}

#endregion

Export-ModuleMember -Function Invoke-Win1337Patch, Invoke-Win1337ElevatedPatch, Resolve-Win1337PatchTarget, New-Win1337ScheduledEntry, Test-Win1337Admin
