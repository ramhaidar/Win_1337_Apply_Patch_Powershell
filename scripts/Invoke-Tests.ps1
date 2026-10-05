#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the Pester test suite with a modern Pester, isolated from legacy host modules.

.DESCRIPTION
    Some Windows hosts still ship Pester 3.x under the Windows PowerShell module path
    (C:\Program Files\WindowsPowerShell\Modules). That legacy copy can shadow the modern module for
    nested Pester calls such as Mock, BeforeAll and InModuleScope, which produces misleading
    "may only be used inside a Describe block" errors even when Pester 5/6 is imported.

    This script removes Windows PowerShell module-path entries for the duration of the run, loads
    the newest available Pester 5+ explicitly, and invokes Pester with Run.Exit so the process exit
    code reflects the test result.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string[]]$TestPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$separator = [System.IO.Path]::PathSeparator
$entries = @($env:PSModulePath -split $separator)
$filtered = @($entries | Where-Object { $_ -notmatch 'WindowsPowerShell' })
if ($filtered.Count -ne $entries.Count) {
    $env:PSModulePath = ($filtered -join $separator)
    Write-Host '[tests] removed legacy Windows PowerShell module paths for this run'
}

$pester = Get-Module -ListAvailable -Name 'Pester' |
    Where-Object { [version]$_.Version -ge [version]'5.0.0' } |
    Sort-Object -Property Version -Descending |
    Select-Object -First 1

if ($null -eq $pester) {
    Write-Host 'Pester 5.x or newer is not installed. Run: pwsh -NoProfile -File ./scripts/Install-DevDependencies.ps1' -ForegroundColor Red
    exit 1
}

Import-Module $pester.Path -Force
Write-Host ("[tests] Pester {0}" -f $pester.Version)

if ($null -eq $TestPath -or $TestPath.Count -eq 0) {
    $TestPath = @(Join-Path $Root 'tests')
}

$config = New-PesterConfiguration
$config.Run.Path = $TestPath
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
