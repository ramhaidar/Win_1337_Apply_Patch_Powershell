#Requires -Version 7.0
<#
.SYNOPSIS
    Single quality-gate entry point for the PowerShell port, mirroring scripts/Verify-Build.ps1 in
    the C# reference repository.

.DESCRIPTION
    Runs, in order, and stops at the first failure:

      1. Syntax / type check  (AST parse + module export-surface check)
      2. Lint + format check  (PSScriptAnalyzer settings + Invoke-Formatter)
      3. Pester test suite

    Each step runs in a child pwsh process so its exit code is isolated and observable; exit code 0
    from this script is the completion evidence for a change. Requires PowerShell 7 and the
    developer modules installed by scripts/Install-DevDependencies.ps1.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$pwsh = (Get-Process -Id $PID).Path
$scripts = Join-Path $Root 'scripts'

$gates = @(
    [pscustomobject]@{ Name = 'Syntax / type check'; Script = 'Test-PowerShellSyntax.ps1' }
    [pscustomobject]@{ Name = 'Lint + format check'; Script = 'Invoke-LintAndFormat.ps1' }
    [pscustomobject]@{ Name = 'Pester tests'; Script = 'Invoke-Tests.ps1' }
)

foreach ($gate in $gates) {
    Write-Host ''
    Write-Host ("==> {0}" -f $gate.Name) -ForegroundColor Cyan

    & $pwsh -NoProfile -File (Join-Path $scripts $gate.Script)
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("Quality gate FAILED at: {0}" -f $gate.Name) -ForegroundColor Red
        exit 1
    }
}

Write-Host ''
Write-Host 'All quality gates passed.' -ForegroundColor Green
exit 0
