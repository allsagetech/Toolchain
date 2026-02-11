Licensing note:
- Versions released before 2026-02-09 were distributed under the MIT License (see LICENSES/OLD-MIT.txt).
- Versions released on or after 2026-02-09 are distributed under the Mozilla Public License 2.0 (see LICENSE).

# Toolchain

A package manager and environment to provide consistent tooling for software teams.

Toolchain manages software packages using container technology and allows users to configure local PowerShell sessions to their need. Toolchain seamlessly integrates common packages with a standardized project script to enable common build commands kept in source control for consistency.

# Requirements

Windows operating system with PowerShell version 5.1 or later.

# Installing

Use this PowerShell command to install Toolchain:

```PowerShell
Install-Module Toolchain -Scope CurrentUser
```

When you want to avoid user prompts, use these PowerShell commands before installation:

```PowerShell
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

Alternatively, if <powershellgallery.com> is not available, you can download or clone this repository and install locally with the `install.ps1` script.

See the [Toolchain PS Gallery](https://www.powershellgallery.com/packages/Toolchain) for other installation methods.

# Updating

Use this PowerShell command to update Toolchain:

```PowerShell
Update-Module Toolchain
```

# Usage

Toolchain is provided by the `Invoke-Toolchain` commandlet. Several aliases are provided for ease-of-use: `toolchain`, `tool`, and `tlc`.

	toolchain [COMMAND]

## Commands

Command | Description
-- | --
[`version`](./doc/toolchain-version.md) | Outputs the version of the module
[`list`](./doc/toolchain-list.md) | Outputs a list of installed packages
[`remote`](./doc/toolchain-remote.md) | Lists remote packages and versions
[`pull`](./doc/toolchain-pull.md) | Downloads packages
[`load`](./doc/toolchain-load.md) | Loads packages into the PowerShell session
[`exec`](./doc/toolchain-exec.md) | Runs a user-defined scriptblock in a managed PowerShell session
[`run`](./doc/toolchain-run.md) | Runs a user-defined scriptblock provided in a project file
[`update`](./doc/toolchain-update.md) | Updates all tagged packages
[`prune`](./doc/toolchain-prune.md) | Deletes unreferenced packages
[`remove`](./doc/toolchain-remove.md) | Untags and deletes packages
[`save`](./doc/toolchain-save.md) | Downloads packages for use in an offline installation
[`help`](./doc/toolchain-help.md) | Outputs usage for this command

## Security and policy

Toolchain supports enterprise controls that are useful for internal and air-gapped environments:

- Signed offline manifests (`toolchain save -Sign`) and optional offline index generation (`-Index`)
- Optional Sigstore/cosign verification during online pulls
- Air-gapped registry support (including an optional TLS-insecure toggle for internal PKI)
- Policy enforcement for allowed tools/versions/registries

See:

- [`policy`](./doc/toolchain-policy.md)
- [`security`](./doc/toolchain-security.md)

# Configuration

## Global

The following variables modify runtime behavior of `toolchain`. Each can be specified as an in-scope variable or an environment variable.

### `ToolchainPullPolicy`

The pull policy determines when a package is downloaded, or pulled, from the upstream registry. It is a `[string]` which can take on the values:

- `"IfNotPresent"` - The package is pulled only when its tag does not exist locally.
- `"Never"` - The package is never pulled. If the tag does not exist, an error is raised.
- `"Always"` - The package is pulled from the upstream registry. If the local tag matches the docker digest, no data is downloaded.

> The default `ToolchainPullPolicy` is `"IfNotPresent"`.

### `ToolchainPath`

The path determines where packages and metadata exist on a user's machine. It is a `[string]`.

> The default `ToolchainPath` is `"$env:LocalAppData\Toolchain"`.

### `ToolchainAutoupdate`

The autoupdate determines if and how often the [update](./doc/toolchain-update.md) action is taken. It is a [`[timespan]`](https://learn.microsoft.com/en-us/dotnet/api/system.timespan) but can be specified and parsed as a `[string]`. The autoupdate mechanism is evaluated upon initialization of the `toolchain` module, meaning once per shell instance in which you use an `toolchain` command.

For example, if `ToolchainAutoupdate` is set to `'1.00:00:00'`, then update will only automatically execute for packages that were last updated at least one day ago.

> The default `ToolchainAutoupdate` is `$null`

### `ToolchainAutoprune`

The autoprune determines if and how often the [prune](./doc/toolchain-prune.md) action is taken. It is a [`[timespan]`](https://learn.microsoft.com/en-us/dotnet/api/system.timespan) but can be specified and parsed as a `[string]`. The autoprune mechanism is evaluated upon initialization of the `toolchain` module, meaning once per shell instance in which you use an `toolchain` command.

For example, if `ToolchainAutoprune` is set to `'1.00:00:00'`, then prune will only automatically execute for packages that have been orphaned for at least one day.

> The default `ToolchainAutoprune` is `$null`.

## Other

### `ProgressPreference`

The progress bar for downloading and extracting packages can be suppressed by assigning the `ProgressPreference` variable to `'SilentlyContinue'`. This behavior is often desirable for environments such as CI pipelines.
## Attribution and trademarks

- License: MPL-2.0 (see `LICENSE.md`). Upstream MIT license text is preserved at `LICENSES/OLD-MIT.txt`.
- Third-party notices: see `ATTRIBUTION.md`.
- Branding: see `TRADEMARKS.md`.

