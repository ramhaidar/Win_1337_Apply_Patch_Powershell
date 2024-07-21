# Win_1337_Apply_Patch

## Description

This PowerShell script is designed to apply/patch 1337 files directly into a .dll or .exe file. It includes modifications to handle permission and ownership changes to ensure successful patching, as recommended by [@VorlonCD](https://github.com/VorlonCD) in [this issue comment](https://github.com/keylase/nvidia-patch/issues/795#issuecomment-2225573296).

## Features

- Apply patches to .dll or .exe files.
- Handles permission and ownership changes to ensure successful patching.
- Removes digital certificates from patched files.
- Updates the checksum of patched files.
- Provides detailed logging of the patching process.
- Create backup files before patching.

## Usage

### Prerequisites

- PowerShell 5.1 or higher.
- Administrative privileges to run the script.
- Patch files (Recommended to be in the same directory as the script) can be downloaded from nvidia-patch repository [here](https://github.com/keylase/nvidia-patch/tree/master/win).

### Parameters

- `-patchFile`: Path to the patch file (mandatory).
- `-targetFile`: Path to the target .dll or .exe file (mandatory).
- `-fixOffset`: Optional switch to adjust the offset during patching.

### Example Commands

```powershell
.\Win_1337_Apply.ps1 -patchFile "nvencodeapi64.1337" -targetFile "C:\Windows\System32\nvencodeapi64.dll" -fixOffset
```

```powershell
.\Win_1337_Apply.ps1 -patchFile "nvencodeapi.1337" -targetFile "C:\Windows\SysWOW64\nvencodeapi.dll" -fixOffset
```

<!-- ### Instructions

1. **Ensure no program is using the target file**:

   - Use Sysinternals Process Explorer to find any handles or DLL files in use and terminate them if necessary.

2. **Run the script with administrative privileges**:

   - The script checks for administrative privileges and will prompt to restart with elevated rights if not run as an administrator.

3. **Follow the script prompts**:
   - The script will unlock the file by changing its owner to "Administrators" and granting full control permissions.
   - It will then apply the patches, remove the digital certificate, and update the checksum of the patched file. -->

### Detailed Process

1. **Permission and Ownership Change**:

   - Changes the owner of the target file to "Administrators".
   - Grants "Administrators" full control permissions.

2. **Patch Application**:

   - Validates the patch instructions.
   - Creates a backup of the original file.
   - Applies the patch instructions to the target file.

3. **Post-Patch Processing**:
   - Removes the digital certificate from the patched file.
   - Updates the file checksum to ensure integrity.

## Credits

This script is based on the work by [Deltafox79](https://github.com/Deltafox79/Win_1337_Apply_Patch) with additional modifications as per [@VorlonCD's](https://github.com/VorlonCD) instructions.
