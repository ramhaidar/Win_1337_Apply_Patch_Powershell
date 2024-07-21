param(
    [Parameter(Mandatory = $true)]
    [string]$patchFile,

    [Parameter(Mandatory = $true)]
    [string]$targetFile,

    [switch]$fixOffset
)

# Function to check if the script is running as administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to restart the script as administrator
function Restart-Elevated {
    $scriptPath = $myInvocation.MyCommand.Definition
    $arguments = "-File `"$scriptPath`" -patchFile `"$patchFile`" -targetFile `"$targetFile`""
    if ($fixOffset) {
        $arguments += " -fixOffset"
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -WorkingDirectory (Get-Location).Path
    exit
}

# Check if running as administrator
if (-not (Test-IsAdmin)) {
    Write-Host "This script must be run as an administrator. Please re-run this script with administrator privileges." -ForegroundColor Red
    timeout /T -1
    exit
}

function Unlock-DLL {
    param (
        [string]$filePath
    )

    # Check if the file exists
    if (-Not (Test-Path -Path $filePath)) {
        Write-Host "The specified file does not exist." -ForegroundColor Red
        exit
    }

    Write-Host "Unlocking file: $filePath" -ForegroundColor Yellow

    # Get the file security object
    $fileSecurity = Get-Acl -Path $filePath

    # Set the owner to "Administrators"
    $administrators = [System.Security.Principal.NTAccount]"Administrators"
    $fileSecurity.SetOwner($administrators)

    # Apply the new owner to the file
    Set-Acl -Path $filePath -AclObject $fileSecurity

    # Define a new access rule for "Administrators" with full control
    $administratorsRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, $administratorsRights, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)

    # Add the new access rule to the file security object
    $fileSecurity.AddAccessRule($accessRule)

    # Apply the updated security settings to the file
    Set-Acl -Path $filePath -AclObject $fileSecurity

    Write-Host "Owner changed to 'Administrators' and full control permissions granted to 'Administrators' for file: $filePath" -ForegroundColor Green
}

function Remove-Certificate {
    param(
        [string]$filePath
    )
    $signature = @"
    [DllImport("imagehlp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool ImageRemoveCertificate(IntPtr handle, int index);
"@
    $type = Add-Type -MemberDefinition $signature -Name "Win32RemoveCertificate" -Namespace "Win32Functions" -PassThru
    Write-Host "Opening file stream for $filePath to remove certificate." -ForegroundColor Yellow
    $fs = New-Object System.IO.FileStream($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    $handle = $fs.SafeFileHandle.DangerousGetHandle()
    Write-Host "Removing certificate from $filePath." -ForegroundColor Yellow
    $result = $type::ImageRemoveCertificate($handle, 0)
    $fs.Close()
    Write-Host "Certificate removal result: $result." -ForegroundColor Green
    return $result
}

function Update-CheckSum {
    param(
        [string]$filePath
    )
    $signature = @"
    [DllImport("imagehlp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern uint MapFileAndCheckSum(string Filename, out uint HeaderSum, out uint CheckSum);
"@
    $type = Add-Type -MemberDefinition $signature -Name "Win32CheckSum" -Namespace "Win32Functions" -PassThru
    $headerSum = 0
    $calculatedSum = 0
    Write-Host "Calculating checksum for $filePath." -ForegroundColor Yellow
    $returnCode = $type::MapFileAndCheckSum($filePath, [ref]$headerSum, [ref]$calculatedSum)
    if ($returnCode -eq 0) {
        Write-Host "Checksum calculation successful. Updating file checksum." -ForegroundColor Yellow
        $fileStream = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
        $br = New-Object System.IO.BinaryReader($fileStream)
        $bw = New-Object System.IO.BinaryWriter($fileStream)
        $data = $br.ReadBytes($br.BaseStream.Length)
        $peHeaderOffset = [System.BitConverter]::ToInt32($data, 0x3C)
        $optionalHeaderOffset = $peHeaderOffset + 24
        $checksumOffset = $optionalHeaderOffset + 64
        $bw.BaseStream.Position = $checksumOffset
        $bw.Write($calculatedSum)
        $bw.Close()
        $br.Close()
        $fileStream.Close()
        Write-Host "Checksum updated successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Checksum calculation failed with return code $returnCode." -ForegroundColor Red
    }
    return $returnCode
}

function Apply-Patch {
    param(
        [string]$exePath,
        [string]$patchPath,
        [switch]$fixOffset
    )
    $baseOffset = 0xC00  # Adjust this base offset as necessary
    $dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    
    if (-not (Test-Path $exePath)) {
        Write-Host "Target executable file does not exist." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $patchPath)) {
        Write-Host "Patch file does not exist." -ForegroundColor Red
        return
    }

    Write-Host "Reading patch instructions from $patchPath." -ForegroundColor Yellow
    $patchInstructions = Get-Content $patchPath
    if ($patchInstructions[0] -notmatch "^>nvencodeapi(?:64)?\.dll$") {
        Write-Host "Invalid patch file format. The first line should be '>nvencodeapi64.dll' atau '>nvencodeapi.dll'." -ForegroundColor Red
        return
    }

    $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
    $version = $fileVersionInfo.FileVersion.Replace(".", "_")
    $backupFilePath = "$($exePath -replace '\.dll$', '').dll.$version.$dateTime.bak"

    Write-Host "Starting patching process..." -ForegroundColor Cyan
    Write-Host "Target executable: $exePath" -ForegroundColor Cyan
    Write-Host "Patch file: $patchPath" -ForegroundColor Cyan
    Write-Host "Fix offset: $fixOffset" -ForegroundColor Cyan

    $exeData = [System.IO.File]::ReadAllBytes($exePath)
    $allOffsetsFound = $true

    Write-Host "Validating patch instructions..." -ForegroundColor Yellow
    foreach ($instruction in $patchInstructions[1..($patchInstructions.Length - 1)]) {
        if ($instruction -match "^(.*?):(.*?)\->(.*?)$") {
            $offset = [Convert]::ToInt32($matches[1], 16)
            $originalByte = [Convert]::ToByte($matches[2], 16)
            if ($fixOffset) {
                $offset -= $baseOffset
            }
            if ($exeData[$offset] -ne $originalByte) {
                Write-Host "Mismatch or offset not found at 0x$($offset.ToString('X')). Expected: 0x$($originalByte.ToString('X')), Found: 0x$($exeData[$offset].ToString('X'))" -ForegroundColor Red
                $allOffsetsFound = $false
                break
            }
            else {
                Write-Host "Offset 0x$($offset.ToString('X')) validated successfully. Found byte: 0x$($exeData[$offset].ToString('X'))" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Invalid instruction format: $instruction" -ForegroundColor Red
            $allOffsetsFound = $false
            break
        }
    }

    if ($allOffsetsFound) {
        Write-Host "All offsets validated successfully." -ForegroundColor Green

        # Unlock the DLL file before patching
        Unlock-DLL -filePath $exePath

        # Create a backup before patching if all offsets are correct
        if (-not (Test-Path $backupFilePath)) {
            Write-Host "Creating a backup of the original file at $backupFilePath." -ForegroundColor Yellow
            Copy-Item -Path $exePath -Destination $backupFilePath
            Write-Host "Backup created successfully." -ForegroundColor Cyan
        }

        # Re-check and apply the patches
        Write-Host "Applying patches..." -ForegroundColor Yellow
        foreach ($instruction in $patchInstructions[1..($patchInstructions.Length - 1)]) {
            if ($instruction -match "^(.*?):(.*?)\->(.*?)$") {
                $offset = [Convert]::ToInt32($matches[1], 16)
                $newByte = [Convert]::ToByte($matches[3], 16)
                if ($fixOffset) {
                    $offset -= $baseOffset
                }
                $originalByte = $exeData[$offset]
                $exeData[$offset] = $newByte
                Write-Host "Patched offset 0x$($offset.ToString('X')). Original byte: 0x$($originalByte.ToString('X')), New byte: 0x$($newByte.ToString('X'))." -ForegroundColor Green
            }
        }

        Write-Host "Writing patched data to $exePath." -ForegroundColor Yellow
        [System.IO.File]::WriteAllBytes($exePath, $exeData)
        Write-Host "Removing digital certificate from patched file." -ForegroundColor Yellow
        Remove-Certificate -filePath $exePath | Out-Null
        Write-Host "Updating checksum of patched file." -ForegroundColor Yellow
        Update-CheckSum -filePath $exePath | Out-Null
        Write-Host "All patches applied successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Patching aborted. No changes were made to the target file." -ForegroundColor Red
    }
}

# Execute the patch function with required parameters
Apply-Patch -exePath $targetFile -patchPath $patchFile -fixOffset:$fixOffset

# Wait for user input before closing
timeout /T -1
