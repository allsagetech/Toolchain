<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function GetRegistryTagsList {
	$api = "/v2/$(GetRegistryRepoName)/tags/list"
	$n = 999
	$last = $null
	$allTags = $null
	while ($true) {
		$ub = [UriBuilder]::new((GetRegistryIndexUrl).Trim().TrimEnd('/'))
		$ub.Path = $api.TrimStart('/')
		$ub.Query = "n=$n" + $(if ($last) { "&last=$([uri]::EscapeDataString($last))" } else { "" })

		$endpoint = $ub.Uri.AbsoluteUri
		$resp = InvokeIndexRegistryRequest -Url $endpoint -Accept 'application/json'
		try {
			$currentTags = $resp | GetJsonResponse
		} finally {
			if ($resp) { $resp.Dispose() }
		}

		if ($null -eq $currentTags) {
			throw 'registry returned an empty tag list response'
		}
		$currentTagValues = @()
		if ($null -ne $currentTags.tags) {
			$currentTagValues = @($currentTags.tags)
		}
		if ($allTags) {
			$allTags.tags = @($allTags.tags) + $currentTagValues
		} else {
			$allTags = [PSCustomObject]@{
				name = $currentTags.name
				tags = $currentTagValues
			}
		}
		if ($currentTagValues.Count -lt $n) {
			return $allTags
		}
		$last = $currentTagValues[$currentTagValues.Count - 1]
	}
}

function GetDockerHubRepositoryTagsList {
	$repo = GetRegistryRepoName
	$parts = $repo.Split('/', 2)
	$namespace = if ($parts.Count -gt 1) { $parts[0] } else { 'library' }
	$repository = if ($parts.Count -gt 1) { $parts[1] } else { $parts[0] }
	$escapedNamespace = [uri]::EscapeDataString($namespace)
	$escapedRepository = [uri]::EscapeDataString($repository)
	$startUrl = "https://hub.docker.com/v2/namespaces/$escapedNamespace/repositories/$escapedRepository/tags?page_size=100"
	$tags = [System.Collections.Generic.List[string]]::new()
	$url = $startUrl
	try {
		while ($url) {
			$uri = [Uri]::new([string]$url, [UriKind]::Absolute)
			if ($uri.Scheme -ne 'https' -or $uri.Host -cne 'hub.docker.com') {
				throw "Docker Hub tag pagination returned an unsafe URL: $url"
			}
			$req = HttpRequest -URL $uri.AbsoluteUri -Accept 'application/json'
			$resp = HttpSend -Req $req
			try {
				$page = $resp | GetJsonResponse
			} finally {
				if ($resp) { $resp.Dispose() }
			}

			foreach ($item in @($page.results)) {
				if ($item.name) {
					$tags.Add([string]$item.name)
				}
			}
			$url = if ($page.next) { [string]$page.next } else { $null }
		}

		return [PSCustomObject]@{
			name = $repo
			tags = @($tags)
		}
	} catch {
		throw "Docker Hub tag API fallback failed for ${startUrl}: $_"
	}
}

function GetTagsList {
	param([switch]$Refresh)

	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		return [PSCustomObject]@{ Name = $repoPath; Tags = (Get-ChildItem $repoPath -Directory -Name) }
	}
	Assert-ToolchainRegistryPolicyAllowed -Action 'list remote packages' -RegistryBaseUrl (GetRegistryBaseUrl) -Repository (GetRegistryRepoName)
	$forceRefresh = $Refresh -or (Test-TruthyValue $env:TOOLCHAIN_CATALOG_REFRESH)
	if (-not $forceRefresh) {
		$cached = Read-ToolchainCatalogCache
		if ($cached) { return $cached }
	}

	try {
		$result = GetRegistryTagsList
	} catch {
		$shouldFallback = (Test-DockerHubRegistryUrl -Url (GetRegistryIndexUrl)) -and ("$_" -match 'HTTP (401|403)')
		if (-not $shouldFallback) {
			$stale = Read-ToolchainCatalogCache -AllowStale
			if ($stale) {
				Write-Warning "Registry tag listing failed; using the last cached catalog: $_"
				return $stale
			}
			throw
		}
		Write-Debug "Docker registry tag list failed; falling back to Docker Hub repository tags API: $_"
		try {
			$result = GetDockerHubRepositoryTagsList
		} catch {
			$stale = Read-ToolchainCatalogCache -AllowStale
			if ($stale) {
				Write-Warning "Docker Hub fallback failed; using the last cached catalog: $_"
				return $stale
			}
			throw
		}
	}
	Write-ToolchainCatalogCache -Catalog $result
	return $result
}
