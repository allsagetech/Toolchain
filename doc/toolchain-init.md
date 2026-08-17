<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# init

Writes a starter declarative `toolchain.yaml` in the current directory.

Toolchain uses `toolchain.yaml` as the project manifest:

- `packages` lists tools, version constraints, named configurations, and explicit dependencies.
- `tlc sync` resolves and locks the complete graph before restoring exact package digests.

Toolchain searches upward for the nearest `toolchain.yaml`, `toolchain.yml`, or
legacy `Toolchain.ps1`. YAML is preferred at the same directory level.

## Usage

    toolchain init [-Force] [-Legacy]

## Example

```powershell
PS C:\repo> toolchain init
Wrote C:\repo\toolchain.yaml

PS C:\repo> notepad .\toolchain.yaml
```

To overwrite an existing file:

```powershell
PS C:\repo> toolchain init -Force
```

Use `tlc init -Legacy` only when an executable `Toolchain.ps1` package list is
required. Optional `Toolchain<Name>` functions for `tlc run` can remain in a
neighboring `Toolchain.ps1` while packages move to YAML.
