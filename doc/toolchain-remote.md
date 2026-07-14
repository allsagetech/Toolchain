<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# remote
Lists remote package versions by category. Registry signatures and other
transport metadata are not installable packages and are excluded from package
views.

## Usage

	toolchain remote list
	toolchain remote models
	toolchain remote all
	toolchain remote tags

- `list` displays ordinary tooling packages by default while retaining model
  properties on the PowerShell object for compatibility with existing scripts.
- `models` returns AI model packages.
- `all` returns every installable package, including tools and models.
- `tags` returns raw registry tags for diagnostics. This view can include
  Cosign `sha256-<digest>.sig` tags and Toolchain package-kind markers.

## Examples

```
PS C:\example> toolchain remote list

somepkg    : {1.2.3, 1.1.0}
anotherpkg : 3.3.1
```

```
PS C:\example> toolchain remote models

qwen3-0.6b            : 2025.7.26+346
smollm2-135m-instruct : 2025.9.22+2043
```

```
PS C:\example> toolchain remote list | select -expand somepkg

Major Minor Patch Build
----- ----- ----- -----
1     2     3
1     1     0
```

Model packages remain valid inputs to `pull`, `load`, `save`, and `exec`; the
category split only changes remote catalog presentation. Scripts that want an
explicit complete catalog should use `remote all`; existing property access such
as `(toolchain remote list).'qwen3-0.6b'` remains supported. Official registries
publish complete, versioned model marker generations such as
`tlc-kind-model-v1-<generation>-<count>--<package>`. Toolchain uses only the
newest complete generation, so an interrupted publication cannot expose a
partial catalog and older markers become inert after a category change. Older
custom registries may set `TOOLCHAIN_MODEL_PACKAGES` to a comma- or
semicolon-separated list until they publish markers.
