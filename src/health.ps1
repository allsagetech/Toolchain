<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Expand-ToolchainHealthCatalogLabel {
	param([Parameter(Mandatory)][string]$Value)

	$compressed = [Convert]::FromBase64String($Value)
	$inputStream = [IO.MemoryStream]::new($compressed, $false)
	$output = [IO.MemoryStream]::new()
	try {
		$gzip = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
		try { $gzip.CopyTo($output) } finally { $gzip.Dispose() }
		if ($output.Length -gt 4194304) { throw 'health catalog exceeds the 4 MiB decoded limit' }
		return [Text.Encoding]::UTF8.GetString($output.ToArray())
	} finally {
		$output.Dispose()
		$inputStream.Dispose()
	}
}

function Get-ToolchainHealthCatalogImageConfig {
	$response = GetResolvedManifestResponse -Ref 'tlc-catalog-v1' -Method GET
	try { $digest = GetDigest -Resp $response } finally { $response.Dispose() }
	if ($digest -notmatch '^sha256:[0-9a-f]{64}$') { throw 'remote health catalog did not resolve to a canonical digest' }
	$registryHost = ([Uri](GetRegistryBaseUrl)).Host
	Invoke-ToolchainCosignVerify -RepoDigestRef "$registryHost/$(GetRegistryRepoName)@$digest"
	return (GetImageConfigJsonFromRef -Ref $digest -ExpectedManifestDigest $digest)
}

function Get-ToolchainHealthCatalog {
	param([switch]$Refresh)

	if (GetToolchainRepo) { return $null }
	if ($Refresh) {
		$script:ToolchainHealthCatalogCache = $null
		$script:ToolchainHealthCatalogCachedAt = $null
	}
	if (-not $Refresh -and $script:ToolchainHealthCatalogCache -and $script:ToolchainHealthCatalogCachedAt -and
		([datetime]::UtcNow - $script:ToolchainHealthCatalogCachedAt) -lt [timespan]::FromMinutes(15)) {
		return $script:ToolchainHealthCatalogCache
	}
	$previousRefresh = $env:TOOLCHAIN_CATALOG_REFRESH
	try {
		if ($Refresh) { $env:TOOLCHAIN_CATALOG_REFRESH = '1' }
		$config = Get-ToolchainHealthCatalogImageConfig
		$labels = if ($config.config -and $config.config.Labels) { $config.config.Labels } else { $config.Labels }
		$value = if ($labels) { [string]$labels.'io.allsagetech.toolchain.healthCatalogGzipBase64' } else { '' }
		if (-not $value) { throw 'remote health catalog label is missing' }
		$catalog = Expand-ToolchainHealthCatalogLabel -Value $value | ConvertFrom-Json
		if ([int]$catalog.schemaVersion -ne 1 -or -not $catalog.generatedAt -or $null -eq $catalog.packages) {
			throw 'remote health catalog has an unsupported schema'
		}
		$script:ToolchainHealthCatalogCache = $catalog
		$script:ToolchainHealthCatalogCachedAt = [datetime]::UtcNow
		return $catalog
	} catch {
		Write-Debug "remote health catalog unavailable: $_"
		return $null
	} finally {
		$env:TOOLCHAIN_CATALOG_REFRESH = $previousRefresh
	}
}

function Protect-ToolchainRemoteCatalogWithHealthPolicy {
	param(
		[Parameter(Mandatory)][hashtable]$Catalog,
		[switch]$Refresh
	)
	$health = Get-ToolchainHealthCatalog -Refresh:$Refresh
	if (-not $health) { return $Catalog }
	$allowed = @{}
	foreach ($entry in @($health.packages)) {
		$versions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
		foreach ($version in @($entry.versions)) { [void]$versions.Add([string]$version) }
		foreach ($name in @([string]$entry.name) + @($entry.aliases | ForEach-Object { [string]$_ })) {
			if ($name) { $allowed[$name] = $versions }
		}
	}
	foreach ($name in @($Catalog.Keys)) {
		if (-not $allowed.ContainsKey([string]$name)) {
			$Catalog.Remove($name)
			continue
		}
		$Catalog[$name] = @($Catalog[$name] | Where-Object { $allowed[[string]$name].Contains([string]($_ | AsTagString)) })
		if (@($Catalog[$name]).Count -eq 0) { $Catalog.Remove($name) }
	}
	return $Catalog
}

function Get-ToolchainPackageHealth {
	param(
		[string]$Package,
		[switch]$OnlyProblems,
		[switch]$Refresh
	)

	$catalog = Get-ToolchainHealthCatalog -Refresh:$Refresh
	$entries = if ($catalog) {
		@($catalog.packages)
	} else {
		$remote = GetDockerTags -Kind All -Refresh:$Refresh -SkipHealthPolicy
		@($remote.PSObject.Properties | ForEach-Object {
			[pscustomobject]@{
				name = $_.Name
				state = 'available'
				reason = 'Live registry fallback; signed health metadata is unavailable.'
				versions = @($_.Value | ForEach-Object { $_.ToString() })
				platforms = @()
				lastScannedAt = $null
				digest = $null
				upstream = $null
			}
		})
	}
	if ($Package) { $entries = @($entries | Where-Object { [string]$_.name -ieq $Package }) }
	if ($OnlyProblems) { $entries = @($entries | Where-Object { [string]$_.state -ine 'available' }) }
	if ($Package -and $entries.Count -eq 0) { throw "remote package health not found: $Package" }
	return @($entries | Sort-Object -Property name | ForEach-Object {
		[pscustomobject]@{
			PSTypeName = 'Toolchain.PackageHealth'
			Name = [string]$_.name
			State = [string]$_.state
			Reason = [string]$_.reason
			Versions = @($_.versions)
			BlockedVersions = [string[]]@($_.blockedVersions | Where-Object { $null -ne $_ -and [string]$_ })
			Platforms = @($_.platforms)
			LastScannedAt = if ($_.lastScannedAt) { [datetime]::Parse([string]$_.lastScannedAt).ToLocalTime() } else { $null }
			Digest = [string]$_.digest
			Upstream = [string]$_.upstream
		}
	})
}
