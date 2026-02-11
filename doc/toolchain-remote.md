<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# remote
Outputs an object of remote packages and versions.

## Usage

	toolchain remote list

## Examples

```
PS C:\example> toolchain remote list

somepkg    : {1.2.3, 1.1.0}
anotherpkg : 3.3.1
```

```
PS C:\example> toolchain remote list | select -expand somepkg

Major Minor Patch Build
----- ----- ----- -----
1     2     3
1     1     0
```
