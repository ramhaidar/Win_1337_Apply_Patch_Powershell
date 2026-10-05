@{
    RootModule           = 'Win1337Patch.psm1'
    ModuleVersion        = '2.4.0'
    GUID                 = 'b7f1c9a2-4e6d-4f2b-9c3a-5d8e7f6a1b04'
    Author               = 'ramhaidar (PowerShell port); original Win_1337_Apply_Patch by DeltaFoX (DeFconX)'
    CompanyName          = 'Community'
    Copyright            = 'GNU General Public License v3.0'
    Description          = 'Core engine for applying text-based .1337 byte patches to Windows .exe/.dll files. PowerShell port of Win_1337_Apply_Patch v2.4.'
    PowerShellVersion    = '7.0'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Invoke-Win1337Patch',
        'Invoke-Win1337ElevatedPatch',
        'Resolve-Win1337PatchTarget',
        'New-Win1337ScheduledEntry',
        'Test-Win1337Admin'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('1337', 'patch', 'nvencodeapi', 'nvidia', 'windows', 'PE')
            LicenseUri   = 'https://www.gnu.org/licenses/gpl-3.0.html'
            ProjectUri   = 'https://github.com/ramhaidar/Win_1337_Apply_Patch_Powershell'
            ReleaseNotes = 'Parity with Win_1337_Apply_Patch v2.4: target-name validation, re-validation on the exclusive writable stream, opt-in ownership fallback, one-shot elevation, RunOnce scheduling, and PE checksum normalization.'
        }
    }
}
