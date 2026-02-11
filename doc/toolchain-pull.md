<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# pull

Downloads packages.

If a package is pulled whose digest exists locally, a new tag for the package is formed.

An array of packages are accepted as input.

## Usage

	toolchain pull <package>[:tag]...

## Example

```
PS C:\example> toolchain pull somepkg
Pulling somepkg:latest
Digest: sha256:db2a58b317e90e537aa1e9b9ab4f1875689bcd9d25a20abdfbf96d3cb0a5ec45
d47df44424b8: Pull complete
Status: Downloaded newer package for somepkg:latest
```
