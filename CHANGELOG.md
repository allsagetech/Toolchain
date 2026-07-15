# Changelog

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
