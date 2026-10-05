#Requires -Version 7.0

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Win1337Patch.psm1'
    Import-Module $script:ModulePath -Force

    function script:New-TestTarget {
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [byte[]]$Bytes = [byte[]](0..255)
        )
        [System.IO.File]::WriteAllBytes($Path, $Bytes)
    }
}

AfterAll {
    Remove-Module Win1337Patch -Force -ErrorAction SilentlyContinue
}

Describe 'Patch engine core' {
    BeforeEach {
        $script:target = Join-Path $TestDrive 'target.dll'
        script:New-TestTarget -Path $script:target
    }

    It 'applies valid patches and mutates the target bytes' {
        $patch = Join-Path $TestDrive 'target.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', '0A:0A->AA', '0B:0B->BB')

        $result = InModuleScope Win1337Patch -Parameters @{ Patch = $patch; Target = $script:target } {
            param($Patch, $Target)
            Invoke-Win1337Core -PatchFilePath $Patch -TargetFilePath $Target -SkipChecksum $true -Log {}
        }

        $result.Success | Should -BeTrue
        $bytes = [System.IO.File]::ReadAllBytes($script:target)
        $bytes[10] | Should -Be 0xAA
        $bytes[11] | Should -Be 0xBB
    }

    It 'writes a backup containing the ORIGINAL bytes' {
        $patch = Join-Path $TestDrive 'target.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', '0A:0A->AA')

        $result = InModuleScope Win1337Patch -Parameters @{ Patch = $patch; Target = $script:target } {
            param($Patch, $Target)
            Invoke-Win1337Core -PatchFilePath $Patch -TargetFilePath $Target -CreateBackup $true -SkipChecksum $true -Log {}
        }

        $result.Success | Should -BeTrue
        $result.BackupPath | Should -Not -BeNullOrEmpty
        [System.IO.File]::Exists($result.BackupPath) | Should -BeTrue
        ([System.IO.File]::ReadAllBytes($result.BackupPath))[10] | Should -Be 0x0A
    }

    It 'rejects a patch whose header lacks the > marker' {
        $patch = Join-Path $TestDrive 'bad.1337'
        Set-Content -LiteralPath $patch -Value @('target.dll', '0A:0A->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.FailureKind | Should -Be 'Validation'
        $result.Message | Should -Match 'valid header'
    }

    It 'rejects a patch whose declared target filename does not match the target' {
        $patch = Join-Path $TestDrive 'wrong.1337'
        Set-Content -LiteralPath $patch -Value @('>other.dll', '0A:0A->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match "not valid for 'target.dll'"
        $result.Message | Should -Match "Expected 'other.dll'"
    }

    It 'accepts a header filename match regardless of case' {
        $patch = Join-Path $TestDrive 'case.1337'
        Set-Content -LiteralPath $patch -Value @('>TARGET.DLL', '0A:0A->AA')

        $result = InModuleScope Win1337Patch -Parameters @{ Patch = $patch; Target = $script:target } {
            param($Patch, $Target)
            Invoke-Win1337Core -PatchFilePath $Patch -TargetFilePath $Target -SkipChecksum $true -Log {}
        }
        $result.Success | Should -BeTrue
    }

    It 'fails on an expected-byte mismatch and leaves the target unchanged' {
        $patch = Join-Path $TestDrive 'mismatch.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', '0A:FF->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match 'mismatch'
        ([System.IO.File]::ReadAllBytes($script:target))[10] | Should -Be 0x0A
    }

    It 'subtracts 0xC00 when -FixOffset is set' {
        $patch = Join-Path $TestDrive 'offset.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', '0C0A:0A->CC')

        $result = InModuleScope Win1337Patch -Parameters @{ Patch = $patch; Target = $script:target } {
            param($Patch, $Target)
            Invoke-Win1337Core -PatchFilePath $Patch -TargetFilePath $Target -FixOffset $true -SkipChecksum $true -Log {}
        }
        $result.Success | Should -BeTrue
        ([System.IO.File]::ReadAllBytes($script:target))[10] | Should -Be 0xCC
    }

    It 'rejects an offset outside the target file' {
        $patch = Join-Path $TestDrive 'range.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', 'FFFFFF:00->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match 'outside the target file'
    }

    It 'rejects invalid hexadecimal' {
        $patch = Join-Path $TestDrive 'hex.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', 'ZZ:00->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
    }

    It 'reports a missing patch file' {
        $result = Invoke-Win1337Patch -PatchFilePath (Join-Path $TestDrive 'nope.1337') -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match 'Patch file not found'
    }

    It 'reports a missing target file' {
        $patch = Join-Path $TestDrive 'target.1337'
        Set-Content -LiteralPath $patch -Value @('>target.dll', '0A:0A->AA')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath (Join-Path $TestDrive 'absent.dll') -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match 'Target file not found'
    }

    It 'reports an empty patch file' {
        $patch = Join-Path $TestDrive 'empty.1337'
        Set-Content -LiteralPath $patch -Value ''
        [System.IO.File]::WriteAllText($patch, '')

        $result = Invoke-Win1337Patch -PatchFilePath $patch -TargetFilePath $script:target -Log {}
        $result.Success | Should -BeFalse
        $result.Message | Should -Match 'empty'
    }
}

Describe 'Patch target resolver' {
    It 'maps nvencodeapi.1337 to the SysWOW64 target' {
        $resolved = Resolve-Win1337PatchTarget -PatchFilePath 'C:\patches\nvencodeapi.1337' -WindowsDirectory 'C:\Windows'
        $resolved | Should -Be 'C:\Windows\SysWOW64\nvEncodeAPI.dll'
    }

    It 'maps nvencodeapi64.1337 to the System32 target' {
        $resolved = Resolve-Win1337PatchTarget -PatchFilePath 'C:\patches\nvencodeapi64.1337' -WindowsDirectory 'C:\Windows'
        $resolved | Should -Be 'C:\Windows\System32\nvEncodeAPI64.dll'
    }

    It 'returns nothing for an unknown patch name' {
        Resolve-Win1337PatchTarget -PatchFilePath 'C:\patches\other.1337' -WindowsDirectory 'C:\Windows' | Should -BeNullOrEmpty
    }
}

Describe 'Patch entry parsing' {
    It 'skips blank lines and parses multiple entries' {
        $lines = @('>target.dll', '', '0A:0A->AA', '  ', '0B:0B->BB')

        $entries = InModuleScope Win1337Patch -Parameters @{ Lines = $lines } {
            param($Lines)
            Get-Win1337PatchEntry -Lines $Lines
        }

        $entries.Count | Should -Be 2
        $entries[0].Offset | Should -Be 0x0A
        $entries[1].Expected | Should -Be 0x0B
    }

    It 'returns nothing when the remainder has no replacement byte' {
        $lines = @('>target.dll', '0A:0A')

        $entries = InModuleScope Win1337Patch -Parameters @{ Lines = $lines } {
            param($Lines)
            Get-Win1337PatchEntry -Lines $Lines
        }
        $entries | Should -BeNullOrEmpty
    }
}
