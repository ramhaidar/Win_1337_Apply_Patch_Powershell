#Requires -Version 7.0
<#
.SYNOPSIS
    Installs the developer-only PowerShell tooling used by the quality gate.

.DESCRIPTION
    Installs Pester 5.x and PSScriptAnalyzer into the current user's module scope. The script is
    idempotent: modules that already satisfy the minimum version are left untouched unless -Force is
    used. Nothing is installed into the machine scope, and the application itself needs none of
    these modules at runtime.
#>
[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$required = [ordered]@{
    Pester           = '5.0.0'
    PSScriptAnalyzer = '1.20.0'
}

foreach ($name in $required.Keys) {
    $minimum = [version]$required[$name]
    $installed = Get-Module -ListAvailable -Name $name |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    if ((-not $Force) -and $null -ne $installed -and [version]$installed.Version -ge $minimum) {
        Write-Host "[ok] $name $($installed.Version) (>= $minimum)"
        continue
    }

    Write-Host "[install] $name >= $minimum (CurrentUser scope)"
    Install-Module -Name $name -MinimumVersion $minimum -Scope CurrentUser -Force -AllowClobber
}

Write-Host 'Developer dependencies are ready.'
