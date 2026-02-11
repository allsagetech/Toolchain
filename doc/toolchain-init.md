<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# init

Writes a starter `Toolchain.ps1` in the current directory.

Toolchain uses `Toolchain.ps1` as the *project file*:

- `$ToolchainPackages` lists the packages that should be available for `pull`, `load`, and `exec`.
- Functions named `Toolchain<Name>` can be invoked via `toolchain run <name>`.

Toolchain will search upward from the current directory to find the nearest `Toolchain.ps1`.

## Usage

    toolchain init [-Force]

## Example

```powershell
PS C:\repo> toolchain init
Wrote C:\repo\Toolchain.ps1

PS C:\repo> notepad .\Toolchain.ps1
```

To overwrite an existing file:

```powershell
PS C:\repo> toolchain init -Force
```
