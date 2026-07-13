# Security policy

## Supported versions

Security fixes are made on the current major release line. Consumers should run the newest published `2.x` release and pin production package references by digest.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability. Use GitHub's private vulnerability-reporting flow for the `allsagetech/toolchain` repository and include the affected version, attack preconditions, a minimal reproducer, and any known mitigations.

## Security boundaries

Toolchain treats registry responses, OCI manifests and layers, package labels, package definitions, and offline repositories as untrusted input. A successful pull must satisfy all of these invariants:

- policy is checked before contacting a registry and again after the immutable version and digest are known;
- manifests, descriptors, and blobs use canonical SHA-256 digests, and installed bytes match the verified digest;
- package definitions remain inside the extracted package root and specification or integrity failures do not fall back silently;
- archive entries cannot escape the package root through paths, links, reparse points, truncated input, or resource exhaustion;
- signed-offline enforcement identifies a configured trusted signer; the presence of any cryptographic signature is not sufficient.

Cosign verification is controlled by policy or `TOOLCHAIN_COSIGN_VERIFY`. Configure a key or both an expected certificate identity and OIDC issuer. Offline CMS verification requires trusted signer thumbprints when signed manifests are required. `TOOLCHAIN_TLS_INSECURE` disables a critical transport control and must be limited to isolated recovery or private-PKI diagnostics.

See [the security command reference](doc/toolchain-security.md) and [the cache migration guide](doc/cache-migration-v2.md).
