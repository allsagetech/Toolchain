<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# load

Loads packages into the PowerShell session.

A package exports one or more environment variables which are defined for the PowerShell session. If the package defines a `$env:Path` variable, it is prepended to the existing value.

An array of packages are accepted as input.

## Usage

	toolchain load <package[:tag]>...

## Example

```
PS C:\example> toolchain load somepkg
Digest: sha256:5987423d9c30b66bbce0ad10337a96bef2e49d69625a1647a769f4df4dc83172
Status: Session configured for somepkg:latest
```
