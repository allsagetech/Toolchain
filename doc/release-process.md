# Release process

Toolchain releases are created only from an immutable `v<version>` tag whose value matches `VERSION` exactly.

The protected `toolchain-release` environment performs these gates:

1. run the complete Windows PowerShell 5.1 and PowerShell 7 suites plus the explicit Linux cross-platform suite;
2. build and import the module artifact;
3. create a SHA-256 checksum and SPDX SBOM;
4. export the canonical versioned package-specification archive and checksum;
5. create GitHub artifact-provenance and SBOM attestations for the module and provenance for the package specification;
6. stage every asset on a draft, publish it, and delete only that new release before failing unless GitHub confirms it is immutable;
7. request a Toolchains consumer promotion using the exact release tag, version, and commit.

Protect the environment with tag restrictions and required reviewers. Keep workflow actions pinned to reviewed commits. A release operator must verify the tag, module checksum, package-spec checksum, SBOM, and GitHub attestations before downstream repositories update their pinned Toolchain revision.

Repository release immutability must be enabled before publishing. GitHub only
applies that setting to future releases, so historical mutable releases remain
historical evidence and are never rewritten. Published releases, tags, assets,
checksums, SBOMs, and attestations are retained indefinitely. CI test logs are
explicitly retained for 14 days. Repository administrators should configure
Actions logs and artifacts to the 90-day repository maximum for public
repositories; workflows may declare a shorter evidence-specific lifetime.

After release publication, `TOOLCHAINS_PROMOTION_TOKEN` dispatches a promotion
request to Toolchains. If that environment secret is unavailable, the release
remains valid and Toolchains' scheduled promotion check is the recovery path.
Toolchains independently re-verifies the tag, commit, `VERSION`, and released
package contract, opens a promotion pull request, and runs real PowerShell 5.1,
PowerShell 7, and Linux consumer tests before merge. Do not point package builds
at a mutable branch as an interim release mechanism.
