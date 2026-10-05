@{
    # PSScriptAnalyzer + Invoke-Formatter settings for the PowerShell port.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # This project is a CLI/GUI-equivalent tool whose primary UX is console output.
        'PSAvoidUsingWriteHost',
        # Patch writes are explicit, non-interactive operations; ShouldProcess/-WhatIf is not part
        # of the v2.4 CLI contract.
        'PSUseShouldProcessForStateChangingFunctions',
        # Internal names mirror the C# reference type names (for example *NativeTypes) rather than
        # cmdlet naming conventions; they are not exported as commands.
        'PSUseSingularNouns',
        # Advanced-formatting alignment (here-strings, ordered maps) is intentional; readability
        # wins over automatic operator spacing.
        'PSUseConsistentWhitespace'
    )

    Rules        = @{
        PSPlaceOpenBrace           = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace          = @{
            Enable             = $true
            NewLineAfter       = $false
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }
        PSUseConsistentIndentation = @{
            Enable              = $true
            Kind                = 'space'
            IndentationSize     = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }
        PSAvoidLongLines           = @{
            Enable            = $true
            MaximumLineLength = 200
        }
        PSAvoidSemicolonsAsLineTerminators = @{
            Enable = $true
        }
    }
}
