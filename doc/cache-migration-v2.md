# Content-cache migration

Toolchain now keys extracted package content by the complete SHA-256 digest instead of the historical 12-character prefix. Full digests prevent two different packages with the same short prefix from sharing a content directory.

Legacy 12-character directories are deliberately never moved or claimed automatically: the directory contains no authoritative ownership marker, so a colliding digest could otherwise claim another package's bytes. When metadata references an installed digest but its full-digest directory is absent, Toolchain performs a verified re-pull into the full-digest location and recreates the package reference. The legacy directory remains untouched until the operator removes it after validation.

Before a large fleet rollout:

1. back up any offline package repository and the local Toolchain cache;
2. deploy the new module to a canary machine and run `toolchain doctor`;
3. pull and execute representative digest-pinned packages;
4. remove legacy short-digest directories only after every supported client has been upgraded and representative packages have been re-pulled.

Do not manually merge two legacy prefix directories. If migration reports a collision or an unexpected reparse point, quarantine the cache and pull the affected packages again from a trusted source.
