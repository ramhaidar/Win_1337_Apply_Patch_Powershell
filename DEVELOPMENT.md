# Development

Open PowerShell 7 in the repository root — the folder containing `Win1337Patch.psm1`. This guide walks through installing the developer tooling, running the quality gate, and testing the engine.

## Requirements

- **Windows** and **PowerShell 7.0+** (`pwsh`). Validated with PowerShell 7.6.6.
- No .NET SDK, Visual Studio, or build step is required: the project is pure PowerShell.

Check your runtime:

```powershell
$PSVersionTable.PSVersion
```

## First-time setup

Install the developer-only modules into your user scope (nothing is installed machine-wide, and the application itself needs none of these at runtime):

```powershell
pwsh -NoProfile -File .\scripts\Install-DevDependencies.ps1
```

This installs **Pester 5+** and **PSScriptAnalyzer** if they are missing or too old. Add `-Force` to reinstall.

## Run the quality gate

`scripts/Verify-Build.ps1` is the **required quality gate** and the same command CI runs. Run it after every change and before reporting a task complete; its exit code `0` is the completion evidence. It runs, in order, and stops at the first failure:

```powershell
pwsh -NoProfile -File .\scripts\Verify-Build.ps1
```

1. **Syntax / type check** — `scripts/Test-PowerShellSyntax.ps1` parses every source file with the PowerShell AST parser, validates the module manifest, and verifies the module's exported functions match the manifest's `FunctionsToExport`.
2. **Lint + format check** — `scripts/Invoke-LintAndFormat.ps1` runs PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1` and checks `Invoke-Formatter` output. It is read-only; pass `-Fix` to rewrite formatting.
3. **Pester tests** — `scripts/Invoke-Tests.ps1` runs the suite with a modern Pester, isolated from any legacy Pester 3 installed under the Windows PowerShell module path.

## Focused commands

| Task | Command |
|---|---|
| Syntax / type check | `pwsh -NoProfile -File .\scripts\Test-PowerShellSyntax.ps1` |
| Lint (read-only) | `pwsh -NoProfile -File .\scripts\Invoke-LintAndFormat.ps1` |
| Lint and auto-format | `pwsh -NoProfile -File .\scripts\Invoke-LintAndFormat.ps1 -Fix` |
| All tests | `pwsh -NoProfile -File .\scripts\Invoke-Tests.ps1` |
| Focused tests | `pwsh -NoProfile -File .\scripts\Invoke-Tests.ps1` with a filtered `tests/` path, or call `Invoke-Pester -Path .\tests\Win1337Patch.Tests.ps1` after `Import-Module Pester -MinimumVersion 5.0.0` |

## Project layout

- `Win1337Patch.psm1` — the engine. All patch validation and apply behavior lives here; do not duplicate it in the entry point.
- `Win_1337_Apply.ps1` — the command-line entry point: parameter binding, module import, output, exit codes.
- `Win1337Patch.psd1` — manifest; keep `FunctionsToExport` in sync with `Export-ModuleMember`.
- `scripts/` — quality-gate tooling and the dependency installer.
- `tests/` — Pester suites.
- `archive/` — the original v1.0 single-file script, kept for reference only.

## Style

- Four-space indentation; brace on the same line (`} else {`), one space around operators.
- `Set-StrictMode -Version 3.0` and `$ErrorActionPreference = 'Stop'` at script/module scope.
- Prefer native cmdlets and .NET APIs over shelling out; pass native arguments as arrays, never concatenated strings.
- Return structured outcome objects for expected failures rather than throwing.
- `PSScriptAnalyzerSettings.psd1` records the enforced baseline (including the few, explained rule exclusions); keep changes there narrow.

## Testing notes

- Use synthetic temporary files under `$TestDrive`; never point the tool or tests at real system DLLs.
- Use the internal `-SkipChecksum` path (reached through `InModuleScope`) for engine tests so no PE/Imagehlp work runs.
- Never trigger real UAC, run `takeown`/`icacls`, or write the `RunOnce` registry key in tests.
- Markdown files in this repository are written with one paragraph per physical line — do not hard-wrap prose.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Pester 5.x or newer is not installed` | Run `scripts/Install-DevDependencies.ps1`. |
| `The Mock command may only be used inside a Describe block` | A legacy Pester 3 is shadowing the modern module; run tests through `scripts/Invoke-Tests.ps1`. |
| Lint reports formatting differences | Run `scripts/Invoke-LintAndFormat.ps1 -Fix` and review the diff. |
| The export-surface check fails | Align `FunctionsToExport` in `Win1337Patch.psd1` with the module's `Export-ModuleMember`. |
