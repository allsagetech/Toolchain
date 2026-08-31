<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Get-ToolchainShellModuleManifestPath {
	$paths = [Collections.Generic.List[string]]::new()
	if ($PSScriptRoot) {
		$paths.Add((Join-Path $PSScriptRoot 'Toolchain.psd1'))
	}

	foreach ($module in @(Get-Module -Name Toolchain)) {
		if ($module.Path) {
			$paths.Add((Join-Path (Split-Path -Parent $module.Path) 'Toolchain.psd1'))
		}
	}

	$command = Get-Command -Name Invoke-Toolchain -ErrorAction SilentlyContinue
	if ($command -and $command.Module -and $command.Module.Path) {
		$paths.Add((Join-Path (Split-Path -Parent $command.Module.Path) 'Toolchain.psd1'))
	}

	foreach ($path in @($paths | Select-Object -Unique)) {
		if (Test-Path -LiteralPath $path -PathType Leaf) {
			return [IO.Path]::GetFullPath($path)
		}
	}

	throw 'could not locate the active Toolchain module manifest for the PowerShell 7 session'
}

function Get-ToolchainManagedPowerShellExecutable {
	param(
		[Parameter(Mandatory)]
		[Collections.Hashtable]$Package
	)

	$digest = $Package | ResolvePackageDigest
	if (-not $digest) { throw 'the Toolchain PowerShell package is not available locally' }
	$root = $digest | ResolvePackagePath
	$executables = @(
		Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'pwsh.exe' -ErrorAction Stop |
			Select-Object -ExpandProperty FullName
	)
	if ($executables.Count -ne 1) {
		throw "Toolchain PowerShell package must contain exactly one pwsh.exe; found $($executables.Count)"
	}
	return [IO.Path]::GetFullPath($executables[0])
}

function Start-ToolchainManagedPowerShell {
	param(
		[Parameter(Mandatory)][string]$Executable,
		[Parameter(Mandatory)][string]$ModuleManifestPath
	)

	$manifestLiteral = $ModuleManifestPath.Replace("'", "''")
	$bootstrap = "`$ErrorActionPreference = 'Stop'; Import-Module -Name '$manifestLiteral' -Force -ErrorAction Stop"
	& $Executable -NoLogo -NoExit -Command $bootstrap
	if ($LASTEXITCODE -ne 0) {
		throw "Toolchain-managed PowerShell exited with code $LASTEXITCODE"
	}
}

function Invoke-ToolchainShell {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet('pwsh')]
		[string]$Command
	)

	$packageRef = 'powershell'
	$null = UpdatePackages -Auto -Packages @($packageRef)
	$package = @(TryEachPackage @($packageRef) { $Input | ResolvePackage } -ActionDescription 'resolve')[0]
	if (-not $package) { throw 'could not resolve the Toolchain PowerShell package' }

	$executable = Get-ToolchainManagedPowerShellExecutable -Package $package
	$manifestPath = Get-ToolchainShellModuleManifestPath
	$launch = {
		param([string]$PwshExecutable, [string]$ToolchainManifestPath)
		Start-ToolchainManagedPowerShell -Executable $PwshExecutable -ModuleManifestPath $ToolchainManifestPath
	}

	ExecuteScript -ScriptBlock $launch -Pkgs @($package) -ArgumentList @($executable, $manifestPath)
}
