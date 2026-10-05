#Requires -Version 7.0
<#
.SYNOPSIS
    Runs PSScriptAnalyzer and the PowerShell formatter over the project.

.DESCRIPTION
    Lint and formatting entry point for the quality gate. By default it is read-only: analyzer
    findings and formatting differences both fail the run. Pass -Fix to rewrite files in place with
    Invoke-Formatter.

    The analyzer and formatter come from PSScriptAnalyzer; if the module is missing the script fails
    with a pointer to scripts/Install-DevDependencies.ps1 rather than silently skipping the gate.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$SettingsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'PSScriptAnalyzerSettings.psd1'),
    [switch]$Fix
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$analyzer = Get-Module -ListAvailable -Name 'PSScriptAnalyzer' |
    Sort-Object -Property Version -Descending |
    Select-Object -First 1
if ($null -eq $analyzer) {
    Write-Host 'PSScriptAnalyzer is not installed. Run: pwsh -NoProfile -File ./scripts/Install-DevDependencies.ps1' -ForegroundColor Red
    exit 1
}

Import-Module $analyzer.Path -Force

$ignoreDirectories = @('bin', 'obj', 'artifacts', 'archive')
$targets = [System.Collections.Generic.List[string]]::new()

$candidateRoots = @(
    $Root
    (Join-Path $Root 'scripts')
    (Join-Path $Root 'tests')
)
foreach ($candidate in $candidateRoots) {
    if (-not (Test-Path -LiteralPath $candidate)) {
        continue
    }

    Get-ChildItem -LiteralPath $candidate -File -ErrorAction SilentlyContinue |
        Where-Object {
            # .psd1 manifests are aligned data files, not code; they are still validated by the
            # syntax/type-check gate, so exclude them from style analysis only.
            $_.Extension -in '.ps1', '.psm1' -and
            -not ($_.FullName.Split([System.IO.Path]::DirectorySeparatorChar) |
                    Where-Object { $ignoreDirectories -contains $_ })
            } |
            ForEach-Object { $targets.Add($_.FullName) }
}

$targets = @($targets | Sort-Object -Unique)
$failed = $false

# --- Analyzer ---
foreach ($target in $targets) {
    $findings = Invoke-ScriptAnalyzer -Path $target -Settings $SettingsPath
    if ($null -ne $findings) {
        $failed = $true
        foreach ($finding in ($findings | Sort-Object Line, RuleName)) {
            Write-Host ("[lint] {0}:{1} {2} {3}" -f $finding.ScriptName, $finding.Line, $finding.Severity, $finding.RuleName) -ForegroundColor Yellow
            Write-Host ("       {0}" -f $finding.Message)
        }
    }
}
if (-not $failed) {
    Write-Host ('[lint] no analyzer findings in {0} files' -f $targets.Count)
}

# --- Formatter ---
$formatter = Get-Command -Name 'Invoke-Formatter' -ErrorAction SilentlyContinue
if ($null -eq $formatter) {
    if ($Fix) {
        Write-Host '[format] Invoke-Formatter unavailable; cannot auto-fix. Update PSScriptAnalyzer.' -ForegroundColor Red
        exit 1
    }
    Write-Host '[format] Invoke-Formatter unavailable; skipping formatting verification.'
} else {
    $formatFailed = $false
    foreach ($target in $targets) {
        $original = Get-Content -LiteralPath $target -Raw
        $formatted = Invoke-Formatter -ScriptDefinition $original -Settings $SettingsPath
        if ($formatted -ne $original) {
            if ($Fix) {
                Set-Content -LiteralPath $target -Value $formatted -Encoding utf8NoBOM -NoNewline
                Write-Host ("[format] fixed {0}" -f (Split-Path -Leaf $target))
            } else {
                $formatFailed = $true
                $failed = $true
                Write-Host ("[format] {0} is not formatted; run with -Fix" -f (Split-Path -Leaf $target)) -ForegroundColor Yellow
            }
        }
    }
    if (-not $formatFailed) {
        Write-Host ('[format] all {0} files formatted' -f $targets.Count)
    }
}

if ($failed) {
    Write-Host 'Lint/format check FAILED.' -ForegroundColor Red
    exit 1
}

Write-Host 'Lint/format check passed.' -ForegroundColor Green
exit 0
