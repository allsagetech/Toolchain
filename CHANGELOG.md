# Changelog

## Unreleased

### Added

- Add component lifecycle actions, including action-only gates, create/deploy phases, command defaults, retries, timeouts, environment and shell selection, deployment output variables, and Kubernetes or network waits.
- Add remote Helm chart packaging from HTTP(S) repositories, OCI registries, direct `.tgz` URLs, and version-pinned Git sources while preserving integrity-indexed offline deployment.
- Add native component image bundling, offline integrity verification, digest-pinned cluster-registry publication, and exact admission mappings for deployment packages.
- Add native top-level package variables with validation, prompting, sensitive/file values, config/environment/CLI overrides, auto-indented templates, and Helm value mappings.
- Add Toolchain-native package metadata, components, required/default/explicit selection, local Helm chart fields, and named manifest groups.
- Add `tlc package create` and `tlc package deploy` for integrity-indexed Kubernetes bundles containing Helm charts, conventional values/configuration, and declared YAML manifests.
- Add safe `tlc audit -Fix` remediation with preview, policy/health/signature refusal gates, atomic lock refresh, package restore, and post-fix verification.
- Expose package-health state-transition and last-clean-scan timestamps for remediation SLO monitoring.
- Add strict `toolchain.yaml` projects with editor schema, version constraints, merged dependency requirements, dependency-first ordering, and cycle detection while retaining legacy `Toolchain.ps1` compatibility.
- Add `tlc sync`, `tlc activate`, and `tlc deactivate` for one-command lock/restore convergence and reversible current-session environments.
- Add native Windows, Linux, and macOS platform detection, portable installation/profile behavior, and macOS client CI coverage.
- Add Docker and Podman auth-file discovery plus Docker credential-helper support for private registries.
- Add Toolchain-native Kubernetes initialization with persistent cluster state, a write-protected node-local OCI registry, exact-match admission mutation, and optional non-interactive Git service setup.
- Add session-scoped `tlc cluster use` and `tlc cluster current` commands for switching between isolated managed cluster kubeconfigs.
- Prompt for optional cluster-init components when `-Components` is omitted, with Git server defaulting to no and explicit non-interactive choices retained.

### Changed

- Stage all release assets on a draft before publication and fail the release workflow unless GitHub confirms immutable-release enforcement.
- Retain CI logs for an explicit 14-day period and document permanent release-evidence retention.
- Verify official `allsagetech/toolchains` package digests with the protected GitHub Actions Cosign identity by default, while preserving explicit policy and diagnostic overrides.
- Disable the bundled Traefik ingress controller in Toolchain-created K3s clusters so ingress remains an explicit operator choice.

### Fixed

- Accept `log_level`, `log_format`, and nested `package.create` and `package.deploy` settings in `toolchain-config.yaml`, including creation templates, deployment variables, component selection, and bundled deploy-time Helm values.
- Resolve relative deployment-package paths from PowerShell's current filesystem location instead of the process launch directory.
- Build and import the admission agent locally when initializing managed clusters, removing the dependency on an unpublished versioned agent image.
- Automatically select a sole managed cluster, refresh K3s kubeconfigs before initialization, distinguish stopped K3s servers, and report actionable Kubernetes API preflight failures.
- Reconcile managed K3s kubeconfigs with the container engine's live published API port and use IPv4 loopback, avoiding stale or unresolvable Docker Desktop endpoints.
- Break the secure-verification bootstrap loop by checksum-verifying a pinned Sigstore Cosign verifier when no compatible application is installed, including Windows PowerShell hosts whose .NET runtime omits architecture data or whose caller uses strict error handling, and report legacy short-digest package caches with an actionable verified-pull recovery message.

## 2.4.0 - 2026-08-15

### Added

- Add built-module regression tests plus expanded update scheduling, completion, and registry transport coverage.
- Add `tlc k9s` with current-context, managed-cluster, and explicit-kubeconfig modes plus native K9s argument forwarding.
- Add optional package filters to `tlc remote list`, `remote models`, and `remote all` for listing one package's versions.
- Add `tlc remote health` and `tlc remote info` for the signed Toolchains package-health catalog.
- Add digest-pinned `tlc lock` and `tlc restore` project workflows.
- Add explicit `tlc verify` verification for package indexes and selected platform manifests.
- Add Docker, Podman, and nerdctl engine selection for local clusters.
- Add authenticated local-registry integration coverage and enforce startup and large-catalog performance budgets.
- Add `tlc audit` with structured and JSON reporting for project/lock drift, installed and remote digests, updates, package health, signature status, and policy violations, plus strict CI enforcement.
- Dispatch successful immutable releases to Toolchains for automated consumer and package-contract promotion.

### Changed

- Make builds root-independent and atomic, enforce the documented 80% coverage floor with exact test dependencies, defer network update checks until first command use, and gate actionable static-analysis rules.
- Hide platform compatibility aliases from the default remote tooling display after a canonical multi-platform index is published.

### Fixed

- Preserve safe Unix permission bits while extracting OCI layers so Linux package executables remain runnable after `tlc pull`.
- Keep auxiliary cache files such as `remote-catalog.json` out of local package-database key enumeration.

## 2.3.3 - 2026-08-14

### Added

- Add detailed command-scoped help through `tlc COMMAND help`, including nested commands such as `tlc cluster create help`.
- Add prefix-style help compatibility through `tlc help COMMAND [SUBCOMMAND]` and help-aware argument completion.

### Changed

- Expand help with command-specific descriptions, usage forms, options, examples, and operational notes.
- Validate help routing without executing the requested command and extend command regression coverage across the full CLI.

## 2.3.2 - 2026-08-14

### Changed

- Restrict normal test and workflow-security push runs to `main`, preventing release tag pushes from duplicating those pipelines.

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
