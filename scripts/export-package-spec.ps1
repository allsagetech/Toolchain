<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

[CmdletBinding()]
param(
	[string]$OutputDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'build')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$specRoot = Join-Path $repoRoot 'schema'
$manifestPath = Join-Path $specRoot 'package-spec.manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version = (Get-Content -LiteralPath (Join-Path $specRoot 'PACKAGE_SPEC_VERSION') -Raw).Trim()
if ($version -ne [string]$manifest.version) {
	throw "Package specification version file '$version' does not match manifest version '$($manifest.version)'."
}

$relativeFiles = @([string]$manifest.schema) + @($manifest.validFixtures) + @($manifest.invalidFixtures)
$builder = New-Object Text.StringBuilder
foreach ($relative in ($relativeFiles | Sort-Object)) {
	$path = Join-Path $specRoot $relative
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
		throw "Package specification file is missing: $relative"
	}
	$content = [IO.File]::ReadAllText($path).Replace("`r`n", "`n").Replace("`r", "`n")
	[void]$builder.Append($relative.Replace('\', '/')).Append("`n").Append($content).Append("`n")
}
$hasher = [Security.Cryptography.SHA256]::Create()
try {
	$contentHash = -join ($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($builder.ToString())) | ForEach-Object { $_.ToString('x2') })
} finally {
	$hasher.Dispose()
}
if ($manifest.contentSha256 -and $contentHash -ne [string]$manifest.contentSha256) {
	throw "Package specification content hash mismatch. Expected $($manifest.contentSha256), got $contentHash. Bump or intentionally update the versioned manifest."
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$stage = Join-Path ([IO.Path]::GetTempPath()) ('toolchain-package-spec-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
	foreach ($relative in $relativeFiles) {
		$destination = Join-Path $stage $relative
		New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
		Copy-Item -LiteralPath (Join-Path $specRoot $relative) -Destination $destination -Force
	}
	Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $stage 'package-spec.manifest.json') -Force
	Copy-Item -LiteralPath (Join-Path $specRoot 'PACKAGE_SPEC_VERSION') -Destination (Join-Path $stage 'PACKAGE_SPEC_VERSION') -Force
	$lock = [ordered]@{
		name = [string]$manifest.name
		version = [int]$manifest.version
		contentSha256 = $contentHash
		canonicalRepository = [string]$manifest.canonicalRepository
	}
	[IO.File]::WriteAllText((Join-Path $stage 'package-spec.lock.json'), ($lock | ConvertTo-Json), [Text.UTF8Encoding]::new($false))

	$archive = Join-Path $OutputDirectory ("{0}.zip" -f $manifest.artifactName)
	if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
	Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
	$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
	[IO.File]::WriteAllText("$archive.sha256", "$archiveHash  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
	[pscustomobject]@{ Path = $archive; Sha256 = $archiveHash; ContentSha256 = $contentHash; Version = [int]$manifest.version }
} finally {
	$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
	$stageFull = [IO.Path]::GetFullPath($stage)
	if (-not $stageFull.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
		throw "Refusing to clean unsafe staging path: $stageFull"
	}
	Remove-Item -LiteralPath $stageFull -Recurse -Force -ErrorAction SilentlyContinue
}
