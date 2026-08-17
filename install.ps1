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

# Install into the CurrentUser module roots used by the active platforms.
$isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
if ($isWindowsHost) {
	$moduleRoots = @(
		(Join-Path (Join-Path $HOME 'Documents') (Join-Path 'PowerShell' 'Modules')),
		(Join-Path (Join-Path $HOME 'Documents') (Join-Path 'WindowsPowerShell' 'Modules'))
	)
} else {
	$moduleRoots = @((Join-Path (Join-Path (Join-Path $HOME '.local') 'share') (Join-Path 'powershell' 'Modules')))
}
$installPaths = @($moduleRoots | ForEach-Object { Join-Path (Join-Path $_ 'Toolchain') $version } | Select-Object -Unique)

Remove-Module Toolchain -ErrorAction SilentlyContinue

foreach ($installPath in $installPaths) {
	if (Test-Path $installPath) {
		Remove-Item -Path $installPath -Recurse -Force
	}

	New-Item -ItemType Directory -Path $installPath -Force | Out-Null
	Copy-Item (Join-Path (Join-Path (Join-Path $PSScriptRoot 'build') 'Toolchain') '*') $installPath -Recurse -Force
}

Import-Module (Join-Path $installPaths[0] 'Toolchain.psd1') -Force

Write-Host "Toolchain $version installed successfully"
