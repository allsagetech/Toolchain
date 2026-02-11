<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# save

Downloads packages for use in an offline installation.

Packages are pulled and saved locally in the specified output directory.

An array of packages are accepted as input.

## Usage

	toolchain save [-Sign] [-Index] <package>[:tag]... <output directory>

## Example

```
PS C:\example> toolchain save somepkg toolchain-cache
Pulling somepkg:latest
Digest: sha256:db2a58b317e90e537aa1e9b9ab4f1875689bcd9d25a20abdfbf96d3cb0a5ec45
d47df44424b8: Pull complete

PS C:\example> toolchain save -Sign -Index somepkg toolchain-cache
# writes manifest.json + manifest.json.p7s per package, plus toolchain.index.json (+ .p7s)
```
