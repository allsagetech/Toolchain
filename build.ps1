<#
Toolchain
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$ErrorActionPreference = 'Stop'

function Expand-ToolchainModuleSource {
	param(
		[Parameter(Mandatory)]
		[string]$Path,
		[Parameter(Mandatory)]
		[hashtable]$Seen
	)

	$fullPath = [IO.Path]::GetFullPath($Path)
	if ($Seen.ContainsKey($fullPath)) { return '' }
	$Seen[$fullPath] = $true

	$sourceRoot = Split-Path -Parent $fullPath
	$content = New-Object Text.StringBuilder
	foreach ($line in [IO.File]::ReadAllLines($fullPath)) {
		if ($line -match '^\s*\.\s+\$PSScriptRoot[\\/](.+\.ps1)\s*$') {
			$relativePath = $Matches[1] -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
			$dependencyPath = Join-Path $sourceRoot $relativePath
			$null = $content.Append((Expand-ToolchainModuleSource -Path $dependencyPath -Seen $Seen))
		} else {
			$null = $content.Append($line).Append("`r`n")
		}
	}
	return $content.ToString()
}

function Get-ToolchainModuleVersion {
	$versionFile = Join-Path $PSScriptRoot 'VERSION'
	if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
		throw "VERSION file does not exist: $versionFile"
	}

	$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
	$parsedVersion = $null
	if (-not [Version]::TryParse($version, [ref]$parsedVersion)) {
		throw "VERSION does not contain a valid module version: $version"
	}
	return $version
}

function Write-AsciiFile {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][string]$Content
	)
	[IO.File]::WriteAllText($Path, $Content, [Text.Encoding]::ASCII)
}

function Test-ToolchainBuiltModule {
	param([Parameter(Mandatory)][string]$ManifestPath)

	$manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
	if ($manifest.ExportedFunctions.Keys -notcontains 'Invoke-Toolchain') {
		throw 'Built module does not export Invoke-Toolchain.'
	}
	foreach ($alias in @('toolchain', 'tool', 'tlc')) {
		if ($manifest.ExportedAliases.Keys -notcontains $alias) {
			throw "Built module does not export alias '$alias'."
		}
	}

	$hostExecutable = (Get-Process -Id $PID -ErrorAction Stop).Path
	$escapedManifestPath = $ManifestPath.Replace("'", "''")
	$validationScript = @"
`$ErrorActionPreference = 'Stop'
`$env:TOOLCHAIN_DISABLE_UPDATE_CHECK = '1'
Import-Module -Name '$escapedManifestPath' -Force -ErrorAction Stop
if (-not (Get-Command Invoke-Toolchain -ErrorAction Stop)) { throw 'Invoke-Toolchain was not imported.' }
if ((Invoke-Toolchain version).ToString() -ne '$($manifest.Version)') { throw 'Built module version command does not match its manifest.' }
"@
	& $hostExecutable -NoLogo -NoProfile -NonInteractive -Command $validationScript
	if ($LASTEXITCODE -ne 0) {
		throw "Built module import validation failed with exit code $LASTEXITCODE."
	}
}

$moduleVersion = Get-ToolchainModuleVersion
$sourceEntry = Join-Path (Join-Path $PSScriptRoot 'src') 'tlc.ps1'
$moduleSource = Expand-ToolchainModuleSource -Path $sourceEntry -Seen @{}

$buildRoot = Join-Path $PSScriptRoot 'build'
if (-not (Test-Path -LiteralPath $buildRoot -PathType Container)) {
	New-Item -Path $buildRoot -ItemType Directory -Force | Out-Null
}

$nonce = [Guid]::NewGuid().ToString('n')
$stageDir = Join-Path $buildRoot "Toolchain.stage.$nonce"
$finalDir = Join-Path $buildRoot 'Toolchain'
$backupDir = Join-Path $buildRoot "Toolchain.backup.$nonce"

try {
	New-Item -Path $stageDir -ItemType Directory -ErrorAction Stop | Out-Null

	Write-AsciiFile -Path (Join-Path $stageDir 'Toolchain.psm1') -Content $moduleSource
	Write-AsciiFile -Path (Join-Path $stageDir 'Toolchain.psd1') -Content @"
@{
	RootModule = 'Toolchain.psm1'
	ModuleVersion = '$moduleVersion'
	CompatiblePSEditions = @('Desktop','Core')
	GUID = '12d99217-b208-4995-8cdf-26e4cf695588'
	PowerShellVersion = '5.1'
	Author = 'AllSageTech'
	CompanyName = 'AllSageTech, LLC'
	Copyright = 'Mozilla Public License Version 2.0'
	Description = 'A package manager and environment to provide consistent tooling for software teams.'
	FunctionsToExport = @('Invoke-Toolchain')
	FormatsToProcess = @('Toolchain.Format.ps1xml')
	CmdletsToExport = @()
	VariablesToExport = ''
	AliasesToExport = @('toolchain', 'tool', 'tlc')
	FileList = @(
		'Toolchain.psm1',
		'Toolchain.Format.ps1xml',
		'schema/toolchain-project.schema.json',
		'README.md',
		'CHANGELOG.md',
		'LICENSE.md',
		'ATTRIBUTION.md',
		'COPYRIGHT.md',
		'TRADEMARKS.md',
		'SECURITY.md'
	)
	PrivateData = @{
		PSData = @{
			Tags = @('windows', 'linux', 'macos', 'docker', 'package-manager', 'package', 'development', 'powershell', 'container', 'configuration', 'toolchain', 'toolchains')
			LicenseUri = 'https://github.com/allsagetech/toolchain/blob/main/LICENSE.md'
			ProjectUri = 'https://github.com/allsagetech/toolchain'
			ReleaseNotes = 'https://github.com/allsagetech/toolchain/blob/main/CHANGELOG.md'
		}
	}
}
"@
	Write-AsciiFile -Path (Join-Path $stageDir 'Toolchain.Format.ps1xml') -Content @"
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
	<ViewDefinitions>
		<View>
			<Name>Toolchain.LocalPackage</Name>
			<ViewSelectedBy><TypeName>LocalPackage</TypeName></ViewSelectedBy>
			<TableControl>
				<TableHeaders />
				<TableRowEntries><TableRowEntry><TableColumnItems>
					<TableColumnItem><PropertyName>Package</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Tag</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Version</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Digest</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Size</PropertyName></TableColumnItem>
				</TableColumnItems></TableRowEntry></TableRowEntries>
			</TableControl>
		</View>
		<View>
			<Name>Toolchain.Cluster</Name>
			<ViewSelectedBy><TypeName>Toolchain.Cluster</TypeName></ViewSelectedBy>
			<TableControl>
				<TableHeaders />
				<TableRowEntries><TableRowEntry><TableColumnItems>
					<TableColumnItem><PropertyName>Name</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Provider</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Status</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Servers</PropertyName></TableColumnItem>
					<TableColumnItem><PropertyName>Workers</PropertyName></TableColumnItem>
				</TableColumnItems></TableRowEntry></TableRowEntries>
			</TableControl>
		</View>
	</ViewDefinitions>
</Configuration>
"@

	foreach ($fileName in @('README.md', 'CHANGELOG.md', 'LICENSE.md', 'ATTRIBUTION.md', 'COPYRIGHT.md', 'TRADEMARKS.md', 'SECURITY.md')) {
		Copy-Item -LiteralPath (Join-Path $PSScriptRoot $fileName) -Destination (Join-Path $stageDir $fileName) -ErrorAction Stop
	}
	$schemaStage = Join-Path $stageDir 'schema'
	New-Item -Path $schemaStage -ItemType Directory -ErrorAction Stop | Out-Null
	Copy-Item -LiteralPath (Join-Path (Join-Path $PSScriptRoot 'schema') 'toolchain-project.schema.json') -Destination $schemaStage -ErrorAction Stop

	Test-ToolchainBuiltModule -ManifestPath (Join-Path $stageDir 'Toolchain.psd1')

	if (Test-Path -LiteralPath $finalDir) {
		Move-Item -LiteralPath $finalDir -Destination $backupDir -ErrorAction Stop
	}
	try {
		Move-Item -LiteralPath $stageDir -Destination $finalDir -ErrorAction Stop
	} catch {
		if ((Test-Path -LiteralPath $backupDir) -and -not (Test-Path -LiteralPath $finalDir)) {
			Move-Item -LiteralPath $backupDir -Destination $finalDir -ErrorAction SilentlyContinue
		}
		throw
	}
	if (Test-Path -LiteralPath $backupDir) {
		Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction Stop
	}
} finally {
	if (Test-Path -LiteralPath $stageDir) {
		Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
	}
}
