# Changelog

## 2.3.1 - 2026-08-14

### Changed

- Label newly initialized PowerShell profile blocks as `Toolchain by AllSageTech`.

### Fixed

- Hide internal `staging-*` publication tags from installable remote catalog views while retaining them in `toolchain remote tags` diagnostics.

## 2.3.0 - 2026-08-14

### Added

- Add `toolchain cluster create`, `list`, `status`, `kubeconfig`, and `delete` for isolated kind, k0s, and k3s-on-k3d development clusters, with Toolchains-managed provider dependencies.

### Changed

- Initialize new PowerShell profiles with the current-user execution policy and a green Toolchain heading, and suppress all output from managed `toolchain load` startup commands.

## 2.2.0 - 2026-08-13

### Added

- Add `toolchain profile init`, `add`, `remove`, `list`, and `path` for safely managing opt-in package loads in the current-user PowerShell profile.

## 2.1.0 - 2026-08-13

### Security

- Fail closed on package-definition specification and integrity errors.
- Bind manifest, descriptor, blob, and extraction processing to canonical SHA-256 digests.
- Harden archive extraction against unsafe links, path traversal, truncated streams, and expansion abuse.
- Require an explicitly trusted identity when signed offline manifests are enforced.

### Changed

- Use complete digests for content-cache identity with migration support for legacy 12-character paths.
- Publish the package-definition schema and conformance fixtures as a versioned contract artifact.
- Split remote discovery into a tooling-first display (`remote list`), model (`remote models`), complete (`remote all`), and raw diagnostic (`remote tags`) views while preserving existing model properties on the `remote list` PowerShell object.
- Exclude Cosign signature and package-kind metadata tags from installable package discovery.
- Cache registry discovery with explicit refresh and stale-if-error behavior.
- Add structured JSON/object diagnostics and command argument completion.
- Split registry transport, remote catalog, and package lifecycle code into focused modules.
- Run the complete test suite on Linux and add a live local OCI registry integration test.
- Publish GitHub release checksums, SBOMs, attestations, and an optional matching PowerShell Gallery package.
