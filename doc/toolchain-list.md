<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# list

Outputs a list of installed packages.

Packages which display a non-sha256 hash are eligible to be updated via the `update` command

When a displayed package has an empty tag, it is considered *orphaned* and eligible to be pruned via the `prune` command.

## Usage

	toolchain list

## Examples

```
PS C:\example> toolchain list

Package    Tag    Digest       Size
-------    ---    ------       ----
somepkg    1      e39f16178524 193.25 MB
anotherpkg latest 9e662865b2ba 349.89 MB
```

```
PS C:\example> toolchain list | where { $_.Package -eq 'somepkg' } | select -expand digest

Sha256
------
sha256:e39f16178524d44ac5ca5323afe09f05b3af2fe28a070ca307f99eb8369535d6
```
