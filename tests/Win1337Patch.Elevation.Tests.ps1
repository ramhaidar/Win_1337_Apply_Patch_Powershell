#Requires -Version 7.0

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Win1337Patch.psm1'
    Import-Module $script:ModulePath -Force
}

AfterAll {
    Remove-Module Win1337Patch -Force -ErrorAction SilentlyContinue
}

Describe 'Windows argument quoting' {
    It 'wraps a simple path in quotes' {
        InModuleScope Win1337Patch {
            ConvertTo-Win1337QuotedArgument -Value 'C:\a b\c d.dll' | Should -Be '"C:\a b\c d.dll"'
        }
    }

    It 'escapes embedded double quotes' {
        InModuleScope Win1337Patch {
            ConvertTo-Win1337QuotedArgument -Value 'a"b' | Should -Be '"a\"b"'
        }
    }

    It 'doubles a trailing backslash before the closing quote' {
        InModuleScope Win1337Patch {
            ConvertTo-Win1337QuotedArgument -Value 'C:\dir\' | Should -Be '"C:\dir\\"'
        }
    }
}

Describe 'Elevated and scheduled command construction' {
    It 'builds elevated worker arguments with the internal marker last' {
        InModuleScope Win1337Patch {
            $arguments = Get-Win1337ElevatedArguments -PatchFilePath 'C:\p\a.1337' -TargetFilePath 'C:\t\a.dll' `
                -FixOffset $true -CreateBackup $true -TakeOwnership $true
            $arguments | Should -Match '^-patch '
            $arguments | Should -Match ' -fileoffset'
            $arguments | Should -Match ' -backup'
            $arguments | Should -Match ' -takeownership'
            $arguments | Should -Match ' -elevatedworker$'
        }
    }

    It 'builds a scheduled command that appends the scheduledrun marker' {
        InModuleScope Win1337Patch {
            $command = Get-Win1337ScheduledCommandLine -ExecutablePath 'C:\app\pwsh.exe' `
                -PatchFilePath 'C:\p\a.1337' -TargetFilePath 'C:\t\a.dll' -CreateBackup $true -Elevate $true
            $command | Should -Match ' -patch '
            $command | Should -Match ' -backup'
            $command | Should -Match ' -elevate'
            $command | Should -Match ' -scheduledrun$'
        }
    }
}

Describe 'Elevation decision logic' {
    It 'returns a pre-mutation access denial unchanged, without launching an elevated worker, when -Elevate is not requested' {
        InModuleScope Win1337Patch {
            Mock Invoke-Win1337Patch {
                New-Win1337Failure -Message 'Access denied.' -FailureKind AccessDenied -Stage TargetWrite
            }
            Mock Invoke-Win1337ElevatedLaunch {
                New-Win1337Success -Message 'should not be called'
            }

            $result = Invoke-Win1337ElevatedPatch -PatchFilePath 'a.1337' -TargetFilePath 'a.dll' -Log {}
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'Use -elevate'
            Should -Invoke Invoke-Win1337ElevatedLaunch -Times 0 -Exactly
        }
    }

    It 'does not retry elevation for a validation failure' {
        InModuleScope Win1337Patch {
            Mock Invoke-Win1337Patch {
                New-Win1337Failure -Message 'Bad header.' -FailureKind Validation -Stage None
            }
            Mock Invoke-Win1337ElevatedLaunch {
                New-Win1337Success -Message 'should not be called'
            }

            $result = Invoke-Win1337ElevatedPatch -PatchFilePath 'a.1337' -TargetFilePath 'a.dll' -Elevate -Log {}
            $result.Success | Should -BeFalse
            $result.Message | Should -Be 'Bad header.'
            Should -Invoke Invoke-Win1337ElevatedLaunch -Times 0 -Exactly
        }
    }

    It 'launches exactly one elevated worker for an eligible denial when -Elevate is set' {
        InModuleScope Win1337Patch {
            Mock Invoke-Win1337Patch {
                New-Win1337Failure -Message 'Access denied.' -FailureKind AccessDenied -Stage TargetWrite
            }
            Mock Invoke-Win1337ElevatedLaunch {
                New-Win1337Success -Message 'Elevated patch operation completed successfully.'
            }

            $result = Invoke-Win1337ElevatedPatch -PatchFilePath 'a.1337' -TargetFilePath 'a.dll' `
                -Elevate -HostExecutable 'pwsh.exe' -ScriptPath 'C:\repo\Win_1337_Apply.ps1' -Log {}
            $result.Success | Should -BeTrue
            Should -Invoke Invoke-Win1337ElevatedLaunch -Times 1 -Exactly
        }
    }

    It 'never re-elevates an already elevated worker' {
        InModuleScope Win1337Patch {
            Mock Invoke-Win1337Patch {
                New-Win1337Failure -Message 'Access denied.' -FailureKind AccessDenied -Stage TargetWrite
            }
            Mock Invoke-Win1337ElevatedLaunch {
                New-Win1337Success -Message 'should not be called'
            }

            $result = Invoke-Win1337ElevatedPatch -PatchFilePath 'a.1337' -TargetFilePath 'a.dll' `
                -Elevate -ElevatedWorker -HostExecutable 'pwsh.exe' -ScriptPath 'C:\repo\Win_1337_Apply.ps1' -Log {}
            $result.Success | Should -BeFalse
            Should -Invoke Invoke-Win1337ElevatedLaunch -Times 0 -Exactly
        }
    }

    It 'reports a cancelled UAC prompt without a retry' {
        InModuleScope Win1337Patch {
            Mock Invoke-Win1337Patch {
                New-Win1337Failure -Message 'Access denied.' -FailureKind AccessDenied -Stage TargetWrite
            }
            Mock Invoke-Win1337ElevatedLaunch {
                New-Win1337Failure -Message 'Administrator operation cancelled by UAC. The elevated patch was not started.' -FailureKind AccessDenied -Stage TargetWrite
            }

            $result = Invoke-Win1337ElevatedPatch -PatchFilePath 'a.1337' -TargetFilePath 'a.dll' `
                -Elevate -HostExecutable 'pwsh.exe' -ScriptPath 'C:\repo\Win_1337_Apply.ps1' -Log {}
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'cancelled by UAC'
            Should -Invoke Invoke-Win1337ElevatedLaunch -Times 1 -Exactly
        }
    }
}
