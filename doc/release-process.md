# Release process

Toolchain releases are created only from an immutable `v<version>` tag whose value matches `VERSION` exactly.

The protected `toolchain-release` environment performs these gates:

1. run the complete Windows PowerShell 5.1 and PowerShell 7 suites plus the explicit Linux cross-platform suite;
2. build and import the module artifact;
3. create a SHA-256 checksum and SPDX SBOM;
4. export the canonical versioned package-specification archive and checksum;
5. create GitHub artifact-provenance and SBOM attestations for the module and provenance for the package specification;
6. publish an immutable GitHub release only after every validation and attestation succeeds.

Protect the environment with tag restrictions and required reviewers. Keep workflow actions pinned to reviewed commits. A release operator must verify the tag, module checksum, package-spec checksum, SBOM, and GitHub attestations before downstream repositories update their pinned Toolchain revision.

The Toolchains repository must be updated to the new immutable Toolchain commit or release only after this workflow succeeds. Test its consumer contract before enabling package publication. Do not point package builds at a mutable branch as an interim release mechanism.
