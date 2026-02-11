<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# exec

Runs a user-defined scriptblock in a managed PowerShell session.

## Usage

    toolchain exec <package[:tag]>... [script block]

## Example

```
PS C:\example> toolchain exec go { go version }

go version go1.20.2 windows/amd64
```
