<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

# Copies the built Toolchain module to the $env:PSModulePath user directory.
# Equivalent to `Install-Module Toolchain -Scope CurrentUser`.
# Useful if powershellgallery.com is not available.

$ErrorActionPreference = 'Stop'

& $PSScriptRoot\build.ps1

$version = (Get-Content "$PSScriptRoot\VERSION" -Raw).Trim()

# Install for both PowerShell 7+ and Windows PowerShell 5.1 (CurrentUser scope)
$pwshModuleRoot  = Join-Path $HOME 'Documents\PowerShell\Modules'
$winpsModuleRoot = Join-Path $HOME 'Documents\WindowsPowerShell\Modules'

$installPaths = @(
	(Join-Path $pwshModuleRoot  "Toolchain\$version"),
	(Join-Path $winpsModuleRoot "Toolchain\$version")
)

Remove-Module Toolchain -ErrorAction SilentlyContinue

foreach ($installPath in $installPaths) {
	if (Test-Path $installPath) {
		Remove-Item -Path $installPath -Recurse -Force
	}

	New-Item -ItemType Directory -Path $installPath -Force | Out-Null
	Copy-Item "$PSScriptRoot\build\Toolchain\*" $installPath -Recurse -Force
}

Import-Module Toolchain -Force

Write-Host "Toolchain $version installed successfully"