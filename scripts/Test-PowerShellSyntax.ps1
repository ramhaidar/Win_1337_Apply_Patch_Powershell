#Requires -Version 7.0
<#
.SYNOPSIS
    Parses every PowerShell source file and checks the module export surface.

.DESCRIPTION
    This is the project's "type check" gate for a scripting language: it runs the PowerShell AST
    parser over all .ps1/.psm1/.psd1 files (catching syntax errors that a plain dot-source would
    only hit at runtime), validates the module manifest, and verifies that the functions the module
    actually exports match the manifest's FunctionsToExport list.

    Exits 0 when everything parses and the export surface is consistent; exits 1 otherwise.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string[]]$Path
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ($null -eq $Path -or $Path.Count -eq 0) {
    $Path = @($Root)
}

$extensions = @('.ps1', '.psm1', '.psd1')
$ignoredDirectories = @('bin', 'obj', 'artifacts', 'archive')

$files = [System.Collections.Generic.List[string]]::new()
foreach ($item in $Path) {
    if (Test-Path -LiteralPath $item -PathType Container) {
        Get-ChildItem -LiteralPath $item -Recurse -File |
            Where-Object {
                $extensions -contains $_.Extension -and
                -not ($_.FullName.Split([System.IO.Path]::DirectorySeparatorChar) |
                        Where-Object { $ignoredDirectories -contains $_ })
                } |
                ForEach-Object { $files.Add($_.FullName) }
    } elseif (Test-Path -LiteralPath $item -PathType Leaf) {
        $files.Add((Resolve-Path -LiteralPath $item).Path)
    } else {
        Write-Host "[parse] missing path: $item" -ForegroundColor Red
        exit 1
    }
}

$failed = $false
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
        $failed = $true
        foreach ($parseError in $errors) {
            Write-Host ("[parse] {0}:{1}:{2} {3}" -f
                (Split-Path -Leaf $file), $parseError.Extent.StartLineNumber, $parseError.Extent.StartColumnNumber, $parseError.Message) -ForegroundColor Red
        }
    } else {
        Write-Host ("[parse] {0} ok" -f (Split-Path -Leaf $file))
    }
}

$manifestPath = Join-Path $Root 'Win1337Patch.psd1'
$modulePath = Join-Path $Root 'Win1337Patch.psm1'
if ((Test-Path -LiteralPath $manifestPath) -and (Test-Path -LiteralPath $modulePath)) {
    $manifest = Test-ModuleManifest -Path $manifestPath
    Import-Module $modulePath -Force

    $declared = @($manifest.ExportedFunctions.Keys | Sort-Object)
    $actual = @(Get-Command -Module 'Win1337Patch' -CommandType Function |
            Select-Object -ExpandProperty Name | Sort-Object)

    $drift = Compare-Object -ReferenceObject $declared -DifferenceObject $actual
    if ($null -ne $drift) {
        $failed = $true
        Write-Host '[exports] manifest and module export surface differ:' -ForegroundColor Red
        $drift | ForEach-Object { Write-Host ("  {0} {1}" -f $_.SideIndicator, $_.InputObject) }
    } else {
        Write-Host ("[exports] {0} functions match the manifest" -f $declared.Count)
    }
}

if ($failed) {
    Write-Host 'Syntax/type check FAILED.' -ForegroundColor Red
    exit 1
}

Write-Host 'Syntax/type check passed.' -ForegroundColor Green
exit 0
