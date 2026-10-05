#Requires -Version 7.0

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:EntryScript = Join-Path $script:Root 'Win_1337_Apply.ps1'

    function script:Get-ParameterMetadata {
        param([string]$Path)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

        $map = @{}
        foreach ($parameter in $ast.ParamBlock.Parameters) {
            $name = $parameter.Name.VariablePath.UserPath
            $aliases = @()
            $switch = $false
            foreach ($attribute in $parameter.Attributes) {
                $typeName = $attribute.TypeName.Name
                if ($typeName -eq 'Alias') {
                    $aliases += $attribute.PositionalArguments | ForEach-Object { $_.Value }
                } elseif ($typeName -eq 'switch' -or $typeName -eq 'SwitchParameter') {
                    $switch = $true
                }
            }
            $map[$name] = [pscustomobject]@{ Name = $name; Aliases = $aliases; IsSwitch = $switch }
        }
        return $map
    }
}

Describe 'Command-line entry point surface' {
    BeforeAll {
        $script:params = script:Get-ParameterMetadata -Path $script:EntryScript
    }

    It 'keeps the v1.0 parameter names usable (PowerShell parameter binding is case-insensitive)' {
        # -patchFile / -targetFile / -fixOffset from v1.0 bind to PatchFile / TargetFile / FixOffset.
        $script:params.ContainsKey('PatchFile') | Should -BeTrue
        $script:params.ContainsKey('TargetFile') | Should -BeTrue
        $script:params.ContainsKey('FixOffset') | Should -BeTrue
        $script:params['PatchFile'].Aliases | Should -Contain 'patch'
        $script:params['FixOffset'].Aliases | Should -Contain 'fileoffset'
    }

    It 'exposes the v2.4 switches' {
        foreach ($switchName in 'FixOffset', 'Backup', 'Elevate', 'TakeOwnership', 'Schedule', 'ScheduledRun', 'ElevatedWorker') {
            $script:params.ContainsKey($switchName) | Should -BeTrue
            $script:params[$switchName].IsSwitch | Should -BeTrue
        }
    }

    It 'offers -help with a short alias' {
        $script:params['Help'].Aliases | Should -Contain 'h'
    }

    It 'prints usage and exits 0 for -help' {
        $output = & pwsh -NoProfile -File $script:EntryScript -help 2>&1
        $LASTEXITCODE | Should -Be 0
        ($output -join "`n") | Should -Match 'Usage:'
    }

    It 'exits 1 when a required path is missing' {
        $output = & pwsh -NoProfile -File $script:EntryScript -patch 'only.1337' 2>&1
        $LASTEXITCODE | Should -Be 1
        ($output -join "`n") | Should -Match 'target file'
    }
}
