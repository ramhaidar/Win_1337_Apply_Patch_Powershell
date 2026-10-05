# Win_1337_Apply_Patch_Powershell

PowerShell port of [Win_1337_Apply_Patch](https://github.com/ramhaidar/Win_1337_Apply_Patch) v2.4: a Windows tool that applies text-based `.1337` byte patches to `.exe` and `.dll` files in place. Where the C# project ships a Windows Forms GUI plus a CLI, this port ships the equivalent command-line engine and tooling in PowerShell — the GUI is intentionally out of scope.

The port tracks the v2.4 behavior of the reference: target-filename validation, re-validation of the current bytes on the exclusive writable stream before any mutation, an opt-in target-only ownership fallback, a one-shot elevated worker, optional RunOnce scheduling, and PE certificate/checksum normalization after a successful write.

> **Warning:** Patching executable files changes them in place and can make them unusable. Work on a copy where possible, enable `-backup`, and verify that the patch file belongs to the exact target binary. Use only files you are authorized to modify. A normal run does not request administrator privileges; protected-file operations require explicit consent.

## Requirements

- **Windows** (the engine uses `Imagehlp.dll`, Windows file security, and the `HKCU` registry).
- **PowerShell 7.0 or newer** (`pwsh`); validated with PowerShell 7.6.6.
- Administrator rights only when a selected operation needs them; writable files patch without elevation.
- A `.1337` patch file and the matching target `.exe` or `.dll`.

The original script required PowerShell 5.1 and always elevated. This port targets PowerShell 7 and adopts the reference least-privilege model instead.

## Repository structure

```text
Win_1337_Apply_Patch_Powershell/
├── Win_1337_Apply.ps1              # Thin command-line entry point (v1.0-compatible parameters + v2.4 switches)
├── Win1337Patch.psm1               # Shared engine: validation, patching, PE ops, elevation, ownership, scheduling
├── Win1337Patch.psd1               # Module manifest (2.4.0) with the exported surface
├── PSScriptAnalyzerSettings.psd1   # Lint/format ruleset
├── scripts/
│   ├── Verify-Build.ps1            # Single quality gate (syntax + lint/format + tests)
│   ├── Test-PowerShellSyntax.ps1   # AST parse + module export-surface check
│   ├── Invoke-LintAndFormat.ps1    # PSScriptAnalyzer + Invoke-Formatter
│   ├── Invoke-Tests.ps1            # Pester runner isolated from legacy Pester 3
│   └── Install-DevDependencies.ps1 # Installs Pester 5+ and PSScriptAnalyzer (CurrentUser)
├── tests/
│   ├── Win1337Patch.Tests.ps1          # Engine behavior
│   ├── Win1337Patch.Cli.Tests.ps1      # Entry-point parameter surface and help/exit codes
│   └── Win1337Patch.Elevation.Tests.ps1 # Quoting, elevation decisions, scheduling command construction
├── archive/Win_1337_Apply.v1.0.ps1.old  # The original v1.0 single-file script, kept for reference
├── .github/workflows/ci.yml        # Lint, type-check and test on windows-2025
└── LICENSE                         # GNU GPLv3
```

## Usage

```powershell
.\Win_1337_Apply.ps1 -patch <1337-file> -target <target-file> [options]
```

The v1.0 parameter names are preserved and bind case-insensitively: `-patchFile`, `-targetFile`, and `-fixOffset` still work.

### Parameters

| Parameter | Aliases | Description |
|---|---|---|
| `-patch` | `-patchFile` | Path to the `.1337` patch file. |
| `-target` | `-targetFile` | Path to the target `.exe` or `.dll` file. |
| `-fixOffset` | `-fileoffset`, `-offset` | Subtract the `0xC00` file-offset adjustment from every declared offset. |
| `-backup` | | Create a uniquely named timestamped `.BAK` copy of the target before patching. |
| `-elevate` | | Permit one UAC administrator operation when normal access fails before any mutation. |
| `-takeOwnership` | | Authorize target-only `takeown`/`icacls` ownership fallback after normal elevated write access fails. Does not authorize elevation by itself. |
| `-schedule` | | Store the patch command in the current user's `RunOnce` key for execution at next login. |
| `-scheduledRun` | | Internal marker added to commands created by the scheduler. |
| `-elevatedWorker` | | Internal one-shot worker marker; it does not grant privileges or bypass validation. |
| `-help` | `-h` | Show usage. |

The process exit code is `0` on success and `1` on validation, patching, or scheduling failure.

### Examples

```powershell
# Apply a patch
.\Win_1337_Apply.ps1 -patch .\patch.1337 -target .\target.dll

# Apply a patch and keep a backup, with the 0xC00 adjustment
.\Win_1337_Apply.ps1 -patch .\patch.1337 -target .\target.dll -backup -fixOffset

# Allow a one-shot administrator operation for an authorized protected target
.\Win_1337_Apply.ps1 -patch .\patch.1337 -target C:\Windows\System32\nvEncodeAPI64.dll -elevate -backup

# Allow ownership fallback only if ordinary elevated access fails
.\Win_1337_Apply.ps1 -patch .\patch.1337 -target C:\Windows\System32\nvEncodeAPI64.dll -elevate -takeOwnership -backup

# Schedule the patch for next login (no implicit elevation or ownership)
.\Win_1337_Apply.ps1 -patch .\patch.1337 -target C:\Windows\System32\nvEncodeAPI64.dll -schedule -backup
```

## `.1337` file format

A `.1337` file identifies an expected target filename and one or more hexadecimal byte replacements:

```text
>target.dll
1A3F:90->EB
1A40:00->90
```

- The header is `>` followed by the expected target filename. The comparison uses the filename only, case-insensitive.
- Each entry is `offset:expected->replacement`; offsets and bytes are hexadecimal.
- The expected byte must match the target at the computed offset, otherwise the patch fails before the target is written.
- With `-fixOffset`, `0xC00` is subtracted from every declared offset.
- Blank lines after the header are ignored.

## Privilege model

The port follows the reference v2.4 least-privilege model rather than the v1.0 forced-elevation behavior:

1. The engine always attempts ordinary access first. Nothing requires administrator rights up front.
2. When an eligible access denial occurs **before** any mutation and `-elevate` is supplied, the process launches **one** elevated child (`pwsh` with the `-elevatedworker` marker). The child re-reads and re-validates the current bytes and exits; the parent waits for its exit code.
3. `-takeOwnership` is separate and opt-in. It runs `takeown.exe /F <file>` and `icacls.exe <file> /grant *S-1-5-32-544:F` for one validated target, only after normal elevated write access fails. It never changes ownership to work around unreadable files, invalid patches, or sharing violations.
4. `-elevatedWorker` and `-scheduledRun` are routing markers, not privilege authorization.

## Automatic target resolution

`Resolve-Win1337PatchTarget` maps these patch filenames to their conventional targets:

| Patch file | Suggested target |
|---|---|
| `nvencodeapi.1337` | `%WINDIR%\SysWOW64\nvEncodeAPI.dll` |
| `nvencodeapi64.1337` | `%WINDIR%\System32\nvEncodeAPI64.dll` |

All other patch files require an explicit `-target`.

## Architecture

- **`Win1337Patch.psm1`** is the single engine shared by the entry point and the tests. Key functions: `Invoke-Win1337Patch` (apply), `Invoke-Win1337ElevatedPatch` (apply with the one-shot elevation decision), `Resolve-Win1337PatchTarget`, `New-Win1337ScheduledEntry`, `Test-Win1337Admin`, plus internal parsing, PE, ownership, and scheduling helpers.
- **`Win_1337_Apply.ps1`** parses the command line, imports the module, and reports the outcome with the correct exit code.
- The engine returns a `Win1337.PatchOutcome` object (`Success`, `Message`, `BackupPath`, `FailureKind`, `Stage`, `TargetMayBeModified`, `CanRetryElevated`) instead of throwing for expected failures.
- `Invoke-Win1337Core` exposes an internal `-SkipChecksum` switch — the PowerShell equivalent of the reference's `internal` test-only path. It is not exported, so production callers cannot skip PE normalization; tests reach it through `InModuleScope`.

## Development

Install the developer-only modules (Pester 5+ and PSScriptAnalyzer) once:

```powershell
pwsh -NoProfile -File .\scripts\Install-DevDependencies.ps1
```

Run the required quality gate — syntax/type check, lint + format verification, then the Pester suite:

```powershell
pwsh -NoProfile -File .\scripts\Verify-Build.ps1
```

Its exit code `0` is the completion evidence for a change. Focused runs:

```powershell
pwsh -NoProfile -File .\scripts\Test-PowerShellSyntax.ps1   # AST parse + export-surface check
pwsh -NoProfile -File .\scripts\Invoke-LintAndFormat.ps1    # add -Fix to rewrite formatting
pwsh -NoProfile -File .\scripts\Invoke-Tests.ps1            # Pester, isolated from legacy Pester 3
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for a walkthrough and [AGENTS.md](AGENTS.md) for contribution rules.

## Testing

The suite uses Pester 5+ and currently contains 32 tests across three files. Tests use synthetic temporary files and the internal `-SkipChecksum` path, so they never perform PE/Imagehlp work, show a window, trigger a UAC prompt, run `takeown`/`icacls`, or write the registry. Elevation and scheduling tests verify command construction and decision logic, not real elevation or registry writes.

`scripts/Invoke-Tests.ps1` removes legacy `WindowsPowerShell` module-path entries for the duration of the run. Without that, a system-installed Pester 3.x can shadow the modern module for nested calls (`Mock`, `BeforeAll`, `InModuleScope`) and produce misleading errors.

## Troubleshooting

- **`Pester 5.x or newer is not installed`** — run `scripts/Install-DevDependencies.ps1`.
- **Misleading "may only be used inside a Describe block" errors** — a legacy Pester 3 is shadowing the modern module; always run tests through `scripts/Invoke-Tests.ps1` (or `scripts/Verify-Build.ps1`).
- **The patch is rejected as invalid** — confirm the first line is a `>` header and that the filename after `>` matches the target filename; the comparison ignores case but not the name.
- **The expected byte does not match** — the patch is for a different binary revision, the target was already modified, or the offset mode is wrong. Restore a known-good backup and verify whether the patch requires `-fixOffset`.
- **A protected file cannot be changed** — first permit a one-shot administrator operation with `-elevate`. Use `-takeOwnership` only when appropriate and explicitly authorized; it runs only after normal elevated write access fails.
- **A scheduled patch does not run** — scheduling uses the invoking user's `HKCU` `RunOnce` entry at next login, not unattended boot. Protected targets need `-elevate` recorded at scheduling time and interactive UAC approval at execution.

## Credits

This project is a PowerShell port of [Win_1337_Apply_Patch](https://github.com/ramhaidar/Win_1337_Apply_Patch), which builds on the original work by [Deltafox79](https://github.com/Deltafox79/Win_1337_Apply_Patch) (DeltaFoX / DeFconX), with ownership-handling guidance from [@VorlonCD](https://github.com/keylase/nvidia-patch/issues/795#issuecomment-2225573296). Patch files are published in the [nvidia-patch](https://github.com/keylase/nvidia-patch/tree/master/win) repository.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
