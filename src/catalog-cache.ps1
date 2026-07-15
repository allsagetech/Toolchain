<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Get-ToolchainCatalogCacheTtl {
	$value = if ($env:TOOLCHAIN_CATALOG_CACHE_TTL) { [string]$env:TOOLCHAIN_CATALOG_CACHE_TTL } else { '00:15:00' }
	try {
		$ttl = [timespan]::Parse($value)
	} catch {
		throw "TOOLCHAIN_CATALOG_CACHE_TTL must be a TimeSpan value: $value"
	}
	if ($ttl -lt [timespan]::Zero) { throw 'TOOLCHAIN_CATALOG_CACHE_TTL cannot be negative.' }
	return $ttl
}

function Get-ToolchainCatalogCachePath {
	return (Join-Path (GetPwrDBPath) 'remote-catalog.json')
}

function Test-ToolchainCatalogCacheIdentity {
	param([Parameter(Mandatory)]$Document)
	return ([string]$Document.registry -ceq [string](GetRegistryBaseUrl)) -and
		([string]$Document.indexRegistry -ceq [string](GetRegistryIndexUrl)) -and
		([string]$Document.repository -ceq [string](GetRegistryRepoName))
}

function Read-ToolchainCatalogCache {
	param([switch]$AllowStale)

	$ttl = Get-ToolchainCatalogCacheTtl
	if ($ttl -eq [timespan]::Zero) { return }
	$path = Get-ToolchainCatalogCachePath
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
	try {
		$document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
		if (-not (Test-ToolchainCatalogCacheIdentity -Document $document)) { return }
		$createdAt = [datetime]::Parse([string]$document.createdAt).ToUniversalTime()
		if (-not $AllowStale -and ([datetime]::UtcNow - $createdAt) -gt $ttl) { return }
		return [pscustomobject]@{
			Name = [string]$document.name
			Tags = @($document.tags | ForEach-Object { [string]$_ })
		}
	} catch {
		Write-Debug "Ignoring invalid remote catalog cache '$path': $_"
		return
	}
}

function Write-ToolchainCatalogCache {
	param([Parameter(Mandatory)]$Catalog)

	if ((Get-ToolchainCatalogCacheTtl) -eq [timespan]::Zero) { return }
	$path = Get-ToolchainCatalogCachePath
	$parent = Split-Path -Parent $path
	MakeDirIfNotExist $parent | Out-Null
	$temp = "$path.partial-$([guid]::NewGuid().ToString('n'))"
	$document = [ordered]@{
		schemaVersion = 1
		createdAt = [datetime]::UtcNow.ToString('o')
		registry = [string](GetRegistryBaseUrl)
		indexRegistry = [string](GetRegistryIndexUrl)
		repository = [string](GetRegistryRepoName)
		name = [string]$Catalog.Name
		tags = @($Catalog.Tags | ForEach-Object { [string]$_ })
	}
	try {
		[IO.File]::WriteAllText($temp, ($document | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
		Move-Item -LiteralPath $temp -Destination $path -Force
	} finally {
		Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
	}
}
