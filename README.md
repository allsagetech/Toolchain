# Toolchain

A PowerShell module that manages *tool packages* (distributed as OCI images) and configures your shell environment consistently across a team.

Toolchain can:

- Pull tools from an OCI registry (Docker Registry API)
- “Load” a tool into your current PowerShell session (sets env vars, updates PATH)
- Run commands in a clean, managed session (`exec`) or via a repo-scoped project file (`run`)
- Support offline / air‑gapped installs (`save` + `$ToolchainRepo`)
- Enforce allow/deny policy and optional signature verification

> **License:** MPL-2.0 (see `LICENSE.md`). Prior upstream MIT license text is preserved at `LICENSES/OLD-MIT.txt`.

## Requirements

- Windows
- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+
- Network access to your OCI registry (unless using offline mode)

Toolchain downloads and extracts OCI layers itself; it does **not** require the Docker daemon.

## Installation

### From PowerShell Gallery

```powershell
Install-Module Toolchain -Scope CurrentUser
Import-Module Toolchain
```

### Offline / no PowerShell Gallery access

This repo includes an installer that builds the module and copies it to your user module path:

```powershell
# from the repo root
.\install.ps1
```

## Quick start

### 1) Create a project file

In your repository root:

```powershell
toolchain init
```

This writes a starter `Toolchain.ps1`. Toolchain searches upward from the current directory to find the nearest `Toolchain.ps1`, so you can run commands from subfolders.

### 2) Choose packages

Edit `Toolchain.ps1`:

```powershell
$ToolchainPackages = @(
  'git:latest',
  'node:22',
  'go:1.22'
)

function ToolchainBuild {
  param([string]$Configuration = 'Release')
  Write-Host "Building ($Configuration)" 
}
```

### 3) Pull tools

```powershell
toolchain pull
```

### 4) Use the tools

Load tools into your *current* session:

```powershell
toolchain load
```

Or run in a clean, managed session that does not permanently modify your current shell:

```powershell
toolchain exec { git --version; node --version }
```

Or run a project command from `Toolchain.ps1`:

```powershell
toolchain run build -Configuration Debug
```

## Commands

| Command | Description | Docs |
|---|---|---|
| `version` | Print module version | `doc/toolchain-version.md` |
| `list` | List installed packages | `doc/toolchain-list.md` |
| `remote list` | List remote packages/tags (or offline repo tags) | `doc/toolchain-remote.md` |
| `pull` | Download packages | `doc/toolchain-pull.md` |
| `load` | Load packages into current session | `doc/toolchain-load.md` |
| `exec` | Run a scriptblock in a managed session | `doc/toolchain-exec.md` |
| `run` | Run a function from `Toolchain.ps1` (optionally under packages) | `doc/toolchain-run.md` |
| `update` | Update all tagged packages | `doc/toolchain-update.md` |
| `prune` | Delete unreferenced packages | `doc/toolchain-prune.md` |
| `remove` / `rm` | Untag/delete packages | `doc/toolchain-remove.md` |
| `save` | Download packages for offline use | `doc/toolchain-save.md` |
| `init` | Write a starter `Toolchain.ps1` | `doc/toolchain-init.md` |
| `doctor` | Print diagnostics for your Toolchain setup | `doc/toolchain-doctor.md` |
| `help` | Show CLI help | `doc/toolchain-help.md` |

## Package reference syntax

Toolchain accepts a few package reference forms:

- **By tag:** `name:tag` (examples: `git:latest`, `node:22`, `go:1.22.3`)
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

Schema reference: `schema/Toolchain.PackageDefinition.schema.json`.

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
- `toolchain remote list` lists the saved tags (folder names)

Tip: use `toolchain doctor` to confirm offline mode is active.

## Policy and security

Toolchain supports:

- Allow/deny policies for registries, repos, packages and versions (`doc/toolchain-policy.md`)
- Optional signed-manifest enforcement for offline repos (CMS/PKCS#7)
- Optional Sigstore/cosign verification for online pulls (`doc/toolchain-security.md`)

### Environment toggles (high-level)

- `TOOLCHAIN_POLICY_PATH` / `$ToolchainPolicyPath` / `$env:ToolchainPolicyPath` — policy discovery
- `TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS=1` — require `manifest.json.p7s` in offline repo
- `TOOLCHAIN_COSIGN_VERIFY=1` — run `cosign verify <registry>/<repo>@sha256:...` (requires `cosign` on PATH)

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
- `TOOLCHAIN_INDEX_REGISTRY` — index API URL used for tag listing (default: `https://index.docker.io`)
- `TOOLCHAIN_REPOSITORY` — repo name (default: `allsagetech/toolchains`)
- `TOOLCHAIN_OS` / `TOOLCHAIN_ARCH` — platform selection when resolving multi-arch manifests (defaults: `windows` / `amd64`)

### Registry authentication

Toolchain supports:

- Bearer token: `TOOLCHAIN_TOKEN`
- Basic auth: `TOOLCHAIN_USERNAME` + `TOOLCHAIN_PASSWORD`

### Network / proxy

- `TOOLCHAIN_PROXY` — proxy URL (example: `http://proxy.corp:3128`)
- `TOOLCHAIN_PROXY_USERNAME` / `TOOLCHAIN_PROXY_PASSWORD` — proxy credentials
- `TOOLCHAIN_HTTP_DISABLE_PROXY=1` — disable proxy usage
- `TOOLCHAIN_HTTP_TIMEOUT_SECONDS` — override HTTP timeout
- `TOOLCHAIN_TLS_INSECURE=1` — disable TLS certificate validation (only for controlled/private PKI environments)

### Convenience: `.env` loading

If you keep local settings in a `.env` file, you can import them into your current PowerShell session:

```powershell
.\load-env.ps1
```

See `.env.example` for supported values.

## Troubleshooting

- `toolchain doctor` prints diagnostics (cache path writability, registry reachability, offline repo status).
- If `cosign` verification is enabled, ensure `cosign` is installed and on `PATH`.
- If you see policy failures, confirm which policy file is being discovered (see `doc/toolchain-policy.md`).

## Development

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

## License

MPL-2.0. See `LICENSE.md`.
