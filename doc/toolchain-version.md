<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# version

Outputs the in-use version of the module.

## Usage

	toolchain <version | v>

## Examples

```
PS C:\example> toolchain version

Major  Minor  Build  Revision
-----  -----  -----  --------
1      2      3      -1
```

```
PS C:\example> "I am using toolchain version $(toolchain v)"
I am using toolchain version 1.2.3
```
