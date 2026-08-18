# Toolchain

A PowerShell module that manages *tool packages* (distributed as OCI images) and configures your shell environment consistently across a team.

Toolchain can:

- Pull tools from an OCI registry (Docker Registry API)
- “Load” a tool into your current PowerShell session (sets env vars, updates PATH)
- Run commands in a clean, managed session (`exec`) or via a repo-scoped project file (`run`)
- Support offline / air‑gapped installs (`save` + `$ToolchainRepo`)
- Enforce allow/deny policy and secure-by-default official-package verification

> **License:** MPL-2.0 (see `LICENSE.md`). Prior upstream MIT license text is preserved at `LICENSES/OLD-MIT.txt`.

## Requirements

- Windows with Windows PowerShell 5.1+ or PowerShell 7+
- Linux or macOS with PowerShell 7+
- Network access to your OCI registry (unless using offline mode)

Toolchain downloads and extracts OCI layers itself; it does **not** require the Docker daemon.

## Installation

### From PowerShell Gallery

```powershell
Install-Module Toolchain -Scope CurrentUser
Import-Module Toolchain
```

Tagged GitHub releases are the canonical immutable artifacts and include SHA-256
checksums, an SPDX SBOM, and GitHub provenance attestations. PowerShell Gallery
receives the same built module when the release environment has its
`PSGALLERY_API_KEY` configured; check `Find-Module Toolchain` if the Gallery
channel is temporarily behind the latest GitHub release.

### Offline / no PowerShell Gallery access

This repo includes an installer that builds the module and copies it to your user module path:

```powershell
# from the repo root
.\install.ps1
```

### Optional: load packages whenever PowerShell starts

Create your current-user PowerShell profile with the execution-policy and
green Toolchain startup header, without adding package loads:

```powershell
toolchain profile init
```

Or create it and add packages explicitly:

```powershell
toolchain profile add node git:latest
```

Toolchain adds only the requested `toolchain load '<package>' *> $null` lines
inside a marked block. It preserves the rest of
`Microsoft.PowerShell_profile.ps1`; see [`profile`](doc/toolchain-profile.md)
for listing, removal, and path commands.

### Local Kubernetes clusters

Toolchain can create isolated development clusters on a running Docker, Podman,
or nerdctl-backed Linux container engine:

```powershell
toolchain cluster create dev -Provider kind -Workers 2
toolchain cluster create podman-dev -Provider kind -Engine podman
toolchain cluster create k3s-dev -Provider k3s -Workers 2
toolchain cluster create k0s-dev -Provider k0s -Image docker.io/k0sproject/k0s:v1.32.4-k0s.0
```

If `kind` or `k3d` is not already on `PATH`, Toolchain automatically resolves
and loads its integrity-checked package from the Toolchains catalog. Kubeconfigs
stay under Toolchain's managed data directory and are never merged into the
default kubeconfig. See [`cluster`](doc/toolchain-cluster.md) for requirements,
topology options, and cleanup commands.

Select a managed cluster for Kubernetes commands in the current PowerShell
process, then inspect the selection at any time:

```powershell
tlc cluster use dev
tlc cluster current
kubectl get nodes
```

When exactly one managed cluster exists and `KUBECONFIG` is unset, Toolchain
selects it automatically. Use `cluster use` only when switching among multiple
managed clusters or away from an explicitly selected context.

Bootstrap Toolchain's registry, state, and exact-match admission agent into that
cluster—or any explicit kubeconfig—without another bootstrap CLI. For managed
clusters, Toolchain builds the admission agent locally and imports it into the
cluster runtime, so initialization does not depend on a published agent image:

```powershell
tlc cluster init dev -Confirm
# The optional Git-server prompt defaults to no. For automation:
tlc cluster init dev -Confirm -Components none
tlc cluster init dev -Confirm -Components git-server
```

Launch K9s against the current kubecontext or a Toolchain-managed cluster:

```powershell
tlc k9s
tlc k9s -Cluster dev
```

Toolchain provisions its K9s package when the executable is not already on
`PATH`, then forwards native K9s arguments. See [`k9s`](doc/toolchain-k9s.md).

## Quick start

### 1) Create a project file

In your repository root:

```powershell
toolchain init
```

This writes a schema-validated `toolchain.yaml`. Toolchain searches upward from the current directory to find the nearest YAML manifest or legacy `Toolchain.ps1`, so commands work from subfolders.

### 2) Choose packages

Edit `toolchain.yaml`:

```yaml
schemaVersion: 1
packages:
  - name: git
    version: latest
  - name: node
    version: ">=22 <25"
  - name: pnpm
    version: latest
    dependencies:
      - name: node
        version: ">=22 <25"
```

### 3) Synchronize tools

```powershell
toolchain sync
```

`sync` resolves the dependency graph and version constraints, writes or reuses
`Toolchain.lock.json`, verifies trust policy, and restores exact platform digests.

### 4) Use the tools

Load tools into your *current* session:

```powershell
toolchain load
```

`toolchain load` is session-safe for repeated use: loading the same reference again is idempotent, and when a reference resolves to a newer digest Toolchain removes old PATH entries before applying the new digest configuration.

Or run in a clean, managed session that does not permanently modify your current shell:

```powershell
toolchain exec { git --version; node --version }
```

Or activate and later restore the current shell environment:

```powershell
toolchain activate
toolchain deactivate
```

Executable project commands remain optional in a neighboring legacy
`Toolchain.ps1` file and use the packages from `toolchain.yaml`:

```powershell
toolchain run build -Configuration Debug
```

### Package and deploy Kubernetes applications

The same `toolchain.yaml` can declare a deployment containing Helm charts and
additional Kubernetes YAML. `toolchain-values.yaml` supplies conventional Helm
overrides and `toolchain-config.yaml` controls namespace and wait behavior:

```yaml
schemaVersion: 1
deployment:
  name: demo
  version: 1.0.0
  namespace: demo-system
  charts:
    - path: charts/demo
      release: demo
  manifests:
    - manifests
```

```powershell
tlc package create .
tlc package deploy .\dist\toolchain-package-demo-1.0.0.tlcpkg -Cluster dev -Confirm
```

Toolchain lints charts, creates an integrity-indexed `.tlcpkg`, verifies every
file before deployment, applies declared YAML, and uses Helm upgrade/install for
repeatable releases. See [`package`](doc/toolchain-package.md).

`toolchain.yaml` may alternatively use Toolchain-native `kind`, `metadata`, and
`components`. Toolchain supports required/default/explicit component
selection plus local `charts[].localPath`, `valuesFiles`, and named manifest
`files`; use `tlc package deploy ... -Components 'name,pattern*,-default-name'`
to override the defaults.

## Commands

| Command | Description | Docs |
|---|---|---|
| `version` | Print module version | `doc/toolchain-version.md` |
| `list` | List installed packages | `doc/toolchain-list.md` |
| `remote list` / `models` / `all` / `health` / `info` / `tags` | List remote packages or inspect signed package health and raw registry metadata | `doc/toolchain-remote.md` |
| `pull` | Download packages | `doc/toolchain-pull.md` |
| `load` | Load packages into current session | `doc/toolchain-load.md` |
| `exec` | Run a scriptblock in a managed session | `doc/toolchain-exec.md` |
| `run` | Run a function from `Toolchain.ps1` (optionally under packages) | `doc/toolchain-run.md` |
| `update` | Update all tagged packages | `doc/toolchain-update.md` |
| `prune` | Delete unreferenced packages | `doc/toolchain-prune.md` |
| `remove` / `rm` | Untag/delete packages | `doc/toolchain-remove.md` |
| `save` | Download packages for offline use | `doc/toolchain-save.md` |
| `init` | Write a starter `toolchain.yaml` | `doc/toolchain-init.md` |
| `lock` / `restore` | Pin project packages by platform digest and restore them exactly | `doc/toolchain-lock.md` |
| `sync` | Converge the manifest, lock, verification, and installed packages | `doc/toolchain-sync.md` |
| `activate` / `deactivate` | Apply and reversibly restore a project environment | `doc/toolchain-activate.md` |
| `verify` | Verify package and platform-index signatures | `doc/toolchain-verify.md` |
| `audit` | Report project/lock drift, installed and remote digest state, updates, health, signatures, and policy findings; safely remediate lock/restore drift with `-Fix` | `doc/toolchain-audit.md` |
| `profile init` / `add` / `remove` / `list` / `path` | Manage startup package loads in your PowerShell profile | `doc/toolchain-profile.md` |
| `package create` / `deploy` | Create and deploy verified Kubernetes bundles with Helm charts and YAML manifests | `doc/toolchain-package.md` |
| `cluster create` / `init` / `list` / `status` / `kubeconfig` / `use` / `current` / `delete` | Manage, select, and natively bootstrap local Toolchain clusters | `doc/toolchain-cluster.md` |
| `k9s` | Launch K9s against the current context or a selected kubeconfig | `doc/toolchain-k9s.md` |
| `doctor` | Print diagnostics for your Toolchain setup | `doc/toolchain-doctor.md` |
| `help` | Show CLI help | `doc/toolchain-help.md` |

Every command has help at the point where it is used:

```powershell
tlc update help
tlc prune help
tlc remote models help
tlc cluster create help
tlc cluster init help
```

`tlc help` still shows the complete command overview. Prefix-style help such as
`tlc help cluster create` is also supported.

## Package reference syntax

Toolchain accepts a few package reference forms:

- **By tag:** `name:tag` (examples: `git:latest`, `node:22`, `go:1.22.3`)
- **By constraint:** `name:^24`, `name:~24.2`, or `name:>=22` (quote expressions containing spaces)
- **Optional config selector:** `name:tag::config` (selects a named configuration inside the package definition)
- **Pinned by digest:** `name@sha256:<digest>` (optionally `::config`)
- **Local unpacked package:** `file:///C:/path/to/unpacked-package` (optionally append `<config>` like `file:///C:/pkg<dev>`)

Notes:

- `latest` resolves to the newest available semver-like tag for a package when possible.
- Tags like `v1.2.3` are accepted; Toolchain will match either `1.2.3` or `v1.2.3` when present.
- Registry tags sometimes represent build metadata using `_` instead of `+`; Toolchain handles both.

## How packages configure your shell

A package provides a *toolchain definition* that maps environment variables to values:

- Inline JSON via image label: `io.allsagetech.toolchain.tlc` (or legacy `toolchain.tlc`)
- A JSON file referenced by label: `io.allsagetech.toolchain.tlcPath` (optionally `...tlcSha256`)
- A definition file at the package root: `.tlc` (or legacy `.pwr`)
- Individual env-var labels: `io.allsagetech.toolchain.env.<NAME>`

A definition **must** have a top-level `env` object. Values may be strings or arrays of strings.

The `${.}` token expands to the package’s extracted root directory (so packages can reference their own files).

Schema reference: `schema/toolchain-definition.schema.json`.

## Offline / air‑gapped workflow

1) On an internet-connected machine, download packages into a folder:

```powershell
toolchain save -Index -Sign git:latest .\toolchain-cache
toolchain save -Index -Sign node:22 .\toolchain-cache
```

2) Copy that folder to the offline environment.

3) Point Toolchain at the offline repo directory:

```powershell
# Either a global variable...
$ToolchainRepo = 'D:\toolchain-cache'

# ...or an environment variable
$env:ToolchainRepo = 'D:\toolchain-cache'
```

With `$ToolchainRepo` set:

- `toolchain pull` reads manifests/blobs from disk (no network)
- `toolchain remote list` lists saved tooling packages; `toolchain remote all` includes every saved package

Tip: use `toolchain doctor` to confirm offline mode is active.

## Policy and security

Toolchain supports:

- Allow/deny policies for registries, repos, packages and versions (`doc/toolchain-policy.md`)
- Optional signed-manifest enforcement for offline repos (CMS/PKCS#7)
- Secure-by-default Sigstore/Cosign verification for official online packages (`doc/toolchain-security.md`)
- Explicit signature verification with `tlc verify`, including both an OCI index and its selected platform manifest

### Environment toggles (high-level)

- `TOOLCHAIN_POLICY_PATH` / `$ToolchainPolicyPath` / `$env:ToolchainPolicyPath` — policy discovery
- `TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS=1` — require `manifest.json.p7s` in offline repo
- `TOOLCHAIN_COSIGN_VERIFY=1|0` — explicitly require or disable Cosign verification (official packages default to required)

## Configuration reference

Toolchain reads configuration from either a global variable (highest priority) or an environment variable.

### Core paths and behavior

- `$ToolchainPath` / `$env:ToolchainPath` — root cache directory (default: `%LocalAppData%\Toolchain`)
- `$ToolchainRepo` / `$env:ToolchainRepo` — offline repository directory (enables offline mode)
- `$ToolchainPullPolicy` / `$env:ToolchainPullPolicy` — `IfNotPresent` (default), `Always`, or `Never`
- `$ToolchainAutoprune` / `$env:ToolchainAutoprune` — timespan (e.g. `7.00:00:00`) for auto-prune on module import
- `$ToolchainAutoupdate` / `$env:ToolchainAutoupdate` — timespan for auto-update checks on module import

### Registry selection

- `TOOLCHAIN_REGISTRY` — base registry URL (default: `https://registry-1.docker.io`)
- `TOOLCHAIN_INDEX_REGISTRY` — index API URL used for tag listing (default: the value of `TOOLCHAIN_REGISTRY`)
- `TOOLCHAIN_REPOSITORY` — repo name (default: `allsagetech/toolchains`)
- `TOOLCHAIN_MODEL_PACKAGES` — optional comma/semicolon-separated model package names for legacy custom registries that do not publish package-kind markers
- `TOOLCHAIN_OS` / `TOOLCHAIN_ARCH` — override native OCI platform detection (`windows`, `linux`, or `darwin`; `amd64` or `arm64`)

### Registry authentication

Toolchain supports:

- Bearer token: `TOOLCHAIN_TOKEN`
- Basic auth: `TOOLCHAIN_USERNAME` + `TOOLCHAIN_PASSWORD`
- Docker `config.json` and Podman/containers `auth.json`
- Per-registry `credHelpers` and global `credsStore` providers, including desktop, OS-keychain, cloud-registry, `pass`, and `secretservice` helpers

Credential precedence and private-registry setup are documented in
[`doc/toolchain-authentication.md`](doc/toolchain-authentication.md).

### Network / proxy

- `TOOLCHAIN_PROXY` — proxy URL (example: `http://proxy.corp:3128`)
- `TOOLCHAIN_PROXY_USERNAME` / `TOOLCHAIN_PROXY_PASSWORD` — proxy credentials
- `TOOLCHAIN_HTTP_DISABLE_PROXY=1` — disable proxy usage
- `TOOLCHAIN_HTTP_TIMEOUT_SECONDS` — override HTTP timeout
- `TOOLCHAIN_TLS_INSECURE=1` — disable TLS certificate validation (only for controlled/private PKI environments)
- `TOOLCHAIN_CATALOG_CACHE_TTL` — remote package catalog cache duration (default: `00:15:00`; set to `00:00:00` to disable)
- `TOOLCHAIN_CATALOG_REFRESH=1` — bypass the catalog cache for the current process
- `TOOLCHAIN_UPDATE_CHECK_TTL` — PowerShell Gallery update-check interval (default: `1.00:00:00`)
- `TOOLCHAIN_DISABLE_UPDATE_CHECK=1` — disable the import-time update check

### Convenience: `.env` loading

If you keep local settings in a `.env` file, you can import them into your current PowerShell session:

```powershell
.\load-env.ps1
```

See `.env.example` for supported values.

## Troubleshooting

- `toolchain doctor` prints diagnostics (cache path writability, registry reachability, offline repo status).
- `toolchain doctor -PassThru` and `toolchain doctor -Json` provide structured diagnostics for automation.
- Add `-Refresh` to `toolchain remote ...` or `toolchain doctor` to bypass cached registry data.
- When Cosign verification is required, Toolchain uses an installed `cosign` application or downloads a pinned Sigstore verifier whose SHA-256 is embedded in the client. Unsupported platforms still require `cosign` on `PATH`.
- If you see policy failures, confirm which policy file is being discovered (see `doc/toolchain-policy.md`).

## Development

The supported Toolchain client runs on Windows, Linux, and macOS. CI covers
Windows PowerShell 5.1 and PowerShell 7 plus the cross-platform project,
environment, OCI registry, package-definition, archive-extraction, and built-module
boundaries on Linux and macOS.

Build the module into `build/Toolchain/`:

```powershell
.\build.ps1
```

Run unit tests (Pester + ScriptAnalyzer):

```powershell
.\test.ps1
```

Install a locally-built copy to your user module path:

```powershell
.\install.ps1
```

Package-definition compatibility is governed by the versioned contract in `schema/`. Run the shared valid/invalid fixture corpus when changing definition parsing, labels, or environment semantics. Release automation exports that contract with `scripts/export-package-spec.ps1`.

Security-sensitive changes must preserve the boundaries described in [`SECURITY.md`](SECURITY.md). Cache-layout changes and the legacy short-digest migration are documented in [`doc/cache-migration-v2.md`](doc/cache-migration-v2.md). Tag and artifact publication is documented in [`doc/release-process.md`](doc/release-process.md), and user-visible changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).

The module boundaries and request flow are summarized in [`doc/architecture.md`](doc/architecture.md).

## License

MPL-2.0. See `LICENSE.md`.
