<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# profile

Creates or manages Toolchain package loads in the current user's
`Microsoft.PowerShell_profile.ps1` for the current PowerShell host.

`profile init` creates the profile and its parent directory only when they are
missing. A new profile sets the current-user execution policy to `Unrestricted`
and prints a green `Toolchain by AllSageTech` heading when PowerShell starts. An existing
profile is never overwritten by `profile init`.

## Usage

```powershell
toolchain profile init
toolchain profile add PACKAGE [PACKAGE...]
toolchain profile remove PACKAGE [PACKAGE...]
toolchain profile list
toolchain profile path
```

## Examples

Create a profile with the Toolchain startup header:

```powershell
PS C:\example> toolchain profile init
PowerShell profile is ready: C:\Users\user\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```

Create the profile if necessary and load Node whenever a new PowerShell session
starts:

```powershell
toolchain profile add node
```

Add more than one package at a time:

```powershell
toolchain profile add git:latest go:1.22
```

The resulting managed section looks like this:

```powershell
Set-ExecutionPolicy -Scope CurrentUser Unrestricted
Write-Host "Toolchain by AllSageTech" -ForegroundColor Green

# >>> Toolchain managed packages >>>
toolchain load 'node' *> $null
toolchain load 'git:latest' *> $null
toolchain load 'go:1.22' *> $null
# <<< Toolchain managed packages <<<
```

Toolchain safely quotes package references, ignores case-only duplicates, and
suppresses all output from managed startup loads. It does not change commands
outside these markers. If the marked section has been manually malformed,
Toolchain stops instead of rewriting the profile.

List only the packages managed by this command:

```powershell
toolchain profile list
```

Remove a managed package:

```powershell
toolchain profile remove node
```

Removing the last managed package removes the marked section but preserves all
other profile content. `profile list` and `profile remove` do not create a
missing profile.

Show the exact profile path selected by PowerShell:

```powershell
toolchain profile path
```
