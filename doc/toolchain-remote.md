<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# remote
Lists remote package versions by category. Registry signatures, temporary
`staging-*` publication tags, and other transport metadata are not installable
packages and are excluded from package views.

## Usage

	toolchain remote list
	toolchain remote list node
	toolchain remote models
	toolchain remote models qwen3-0.6b
	toolchain remote all
	toolchain remote health
	toolchain remote health -OnlyProblems
	toolchain remote info kubectl
	toolchain remote tags
	toolchain remote list -Refresh
	toolchain remote all -Json

- `list` displays ordinary tooling packages by default while retaining model
  properties on the PowerShell object for compatibility with existing scripts.
- `models` returns AI model packages.
- `all` returns every installable package, including tools and models.
- Supplying a package name to `list`, `models`, or `all` returns only that
  package's normalized version strings in descending order.
- `tags` returns raw registry tags for diagnostics. This view can include
  Cosign `sha256-<digest>.sig` tags, temporary `staging-*` tags, and Toolchain
  package-kind markers.
- `health` reads the signed Toolchains health catalog and shows availability,
  quarantine or scanner state, supported platforms, versions, state-transition
  time, latest scan, last clean scan, and upstream location. `-OnlyProblems`
  hides healthy entries.
- `info PACKAGE` returns the health record for exactly one logical package.
- If the signed health catalog is temporarily unavailable, `health` falls back
  to a live registry view and labels the result as fallback metadata.
- When the health catalog is available, ordinary package views and resolution
  expose only versions it marks installable; quarantined and scanner-blocked
  versions remain visible under `BlockedVersions` in health output.
- Catalog content is pinned to its OCI digest. If automatic Cosign verification
  is enabled by Toolchain policy, the catalog signature is verified before use.
- `-Refresh` bypasses the short-lived on-disk catalog cache.
- `-Json` emits the selected view as JSON for CI and other automation.

The last successful catalog is cached for 15 minutes by default and is used as
a stale fallback when a registry is temporarily unavailable. Configure the
duration with `TOOLCHAIN_CATALOG_CACHE_TTL`.

## Examples

```
PS C:\example> toolchain remote list

somepkg    : {1.2.3, 1.1.0}
anotherpkg : 3.3.1
```

```
PS C:\example> toolchain remote list node

22.3.1
22.2.0
20.1.0
```

Use `-Json` with a package filter to emit a JSON array of version strings:

```
PS C:\example> toolchain remote list node -Json
[
  "22.3.1",
  "22.2.0",
  "20.1.0"
]
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
