# Changelog

## Unreleased

### Security

- Fail closed on package-definition specification and integrity errors.
- Bind manifest, descriptor, blob, and extraction processing to canonical SHA-256 digests.
- Harden archive extraction against unsafe links, path traversal, truncated streams, and expansion abuse.
- Require an explicitly trusted identity when signed offline manifests are enforced.

### Changed

- Use complete digests for content-cache identity with migration support for legacy 12-character paths.
- Publish the package-definition schema and conformance fixtures as a versioned contract artifact.
