<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# pull

Downloads packages.

If a package is pulled whose digest exists locally, a new tag for the package is formed.

For reliability, pull operations include retries for common transient failures:

- Registry HTTP retries for `408`, `429`, and `5xx` responses (honoring `Retry-After` when present).
- Local package lock contention retries (for example, when another Toolchain process is updating the same package metadata).

Pulls are content-addressed. Toolchain hashes the manifest response it actually
uses, fetches selected manifests, image configuration, and layers by canonical
SHA-256 descriptor, and verifies every descriptor size and digest before use.
If a multi-platform index does not contain the requested `TOOLCHAIN_OS` and
`TOOLCHAIN_ARCH`, the pull fails with the available platforms instead of using
an arbitrary first manifest.
Resumed layer responses must contain a matching byte range; a server that ignores
the range causes a safe restart from byte zero. Completed temporary layer archives
are removed after extraction.

Extraction rejects absolute or escaping paths, link traversal, truncated tar
records, hard links, and OCI whiteout entries. Package images must use layers that
do not depend on whiteout deletion semantics; whiteouts fail explicitly rather
than producing a silently incorrect merged filesystem. Resource limits can be lowered for constrained hosts with
`TOOLCHAIN_MAX_MANIFEST_BYTES`, `TOOLCHAIN_MAX_CONFIG_BYTES`,
`TOOLCHAIN_MAX_LAYER_BYTES`, `TOOLCHAIN_MAX_PACKAGE_BYTES`,
`TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES`, `TOOLCHAIN_MAX_ARCHIVE_ENTRIES`, and
`TOOLCHAIN_MAX_BLOB_SEGMENTS`; every value is a positive integer byte or count
limit.

Extracted content is stored under the complete SHA-256 digest. Historical
12-character content directories have no trustworthy ownership marker and are
never assigned to a requested digest. When metadata refers to one of these legacy
installs, the next pull verifies and restores the package into its full-digest
directory, then recreates the package reference.

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
