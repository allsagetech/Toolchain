<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# run

Runs a user-defined scriptblock provided in a project file.

## Usage

    toolchain run <script>

## Example

```PowerShell
# .\Toolchain.ps1

function ToolchainPrint {
	"Hello world!"
}
```

```
PS C:\example> toolchain run print
Hello world!
```
