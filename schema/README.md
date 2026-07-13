# Toolchain package specification

This directory is the canonical source for the versioned Toolchain package-definition contract.

- `PACKAGE_SPEC_VERSION` is the integer used by the OCI label `io.allsagetech.toolchain.specVersion`.
- `toolchain-definition.schema.json` is the machine-readable contract.
- `package-spec.manifest.json` lists the files included in the release artifact.
- `fixtures/valid` and `fixtures/invalid` form the shared consumer/producer conformance corpus.

Contract changes require fixture coverage. Backward-compatible clarifications may retain the current version; incompatible syntax or semantics require a new specification version and compatibility handling in the consumer. Build the distributable artifact with `scripts/export-package-spec.ps1`.
