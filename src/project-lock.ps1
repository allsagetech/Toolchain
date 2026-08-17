<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Get-ToolchainLockPath {
	param([string]$Path)
	if ($Path) { return [IO.Path]::GetFullPath($Path) }
	$config = if (Get-Command Find-ToolchainProjectConfig -ErrorAction SilentlyContinue) { Find-ToolchainProjectConfig } else { FindConfig }
	$root = if ($config) { Split-Path -Parent $config } else { (Get-Location).Path }
	return (Join-Path $root 'Toolchain.lock.json')
}

function Get-ToolchainRemotePackageLockEntry {
	param([Parameter(Mandatory)][string]$Reference)

	$package = $Reference | AsPackage
	Assert-ToolchainPolicyAllowed -Package $package.Package -Tag ($package.Tag | AsTagString) -Action 'lock'
	$remoteRef = ResolveDockerRef -Pkg $package
	$response = GetResolvedManifestResponse -Ref $remoteRef -Method GET
	try { $digest = GetDigest -Resp $response } finally { $response.Dispose() }
	if (-not $digest) { throw "registry did not return a digest for $Reference" }
	return [ordered]@{
		package = [string]$package.Package
		reference = $Reference
		version = [string]$package.Version
		digest = [string]$digest
		configuration = [string]$package.Config
		platform = "$(GetRegistryPlatformOs)/$(GetRegistryPlatformArch)"
	}
}

function Invoke-ToolchainLock {
	[CmdletBinding()]
	param(
		[string[]]$Packages,
		[string]$Path,
		[string[]]$Update,
		[string]$ProjectDigest
	)

	if (-not $Packages) {
		if (Get-Command Read-ToolchainProject -ErrorAction SilentlyContinue) {
			$project = Read-ToolchainProject
			$Packages = @($project.Packages)
			$ProjectDigest = [string]$project.Digest
		} else {
			$Packages = GetConfigPackages
		}
	}
	if (-not $Packages) { throw 'no packages provided and no Toolchain project package list was found' }
	$lockPath = Get-ToolchainLockPath -Path $Path
	$existing = @{}
	if ($Update -and (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
		$old = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
		foreach ($entry in @($old.packages)) { $existing[[string]$entry.package] = $entry }
	}
	$entries = foreach ($reference in $Packages) {
		$name = [string](($reference | AsPackage).Package)
		if ($Update -and $name -notin $Update -and $existing.ContainsKey($name)) { $existing[$name] }
		else { Get-ToolchainRemotePackageLockEntry -Reference $reference }
	}
	$document = [ordered]@{
		schemaVersion = 1
		generatedAt = [datetime]::UtcNow.ToString('o')
		registry = GetRegistryBaseUrl
		repository = GetRegistryRepoName
		projectDigest = $ProjectDigest
		packages = @($entries)
	}
	$parent = Split-Path -Parent $lockPath
	if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
	$temp = "$lockPath.$([Guid]::NewGuid().ToString('n')).tmp"
	$backup = "$lockPath.$([Guid]::NewGuid().ToString('n')).bak"
	try {
		[IO.File]::WriteAllText($temp, (($document | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
		if (Test-Path -LiteralPath $lockPath) { [IO.File]::Replace($temp, $lockPath, $backup) }
		else { [IO.File]::Move($temp, $lockPath) }
	} finally {
		if (Test-Path -LiteralPath $temp) { [IO.File]::Delete($temp) }
		if (Test-Path -LiteralPath $backup) { [IO.File]::Delete($backup) }
	}
	Write-ToolchainInfo "Wrote $lockPath"
	return $document
}

function Read-ToolchainLock {
	param([string]$Path)
	$lockPath = Get-ToolchainLockPath -Path $Path
	if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw "Toolchain lock file not found: $lockPath" }
	$document = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
	if ([int]$document.schemaVersion -ne 1 -or $null -eq $document.packages) { throw "invalid Toolchain lock file: $lockPath" }
	if ($document.projectDigest -and [string]$document.projectDigest -notmatch '^sha256:[0-9a-fA-F]{64}$') { throw "invalid project digest in Toolchain lock file: $lockPath" }
	foreach ($entry in @($document.packages)) {
		if ([string]$entry.package -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' -or [string]$entry.digest -notmatch '^sha256:[0-9a-fA-F]{64}$') {
			throw "invalid package entry in Toolchain lock file: $lockPath"
		}
	}
	return $document
}

function Invoke-ToolchainRestore {
	[CmdletBinding()]
	param([string]$Path)
	$document = Read-ToolchainLock -Path $Path
	$references = @($document.packages | ForEach-Object {
		$config = if ($_.configuration) { [string]$_.configuration } else { 'default' }
		"$($_.package)@$($_.digest)::$config"
	})
	TryEachPackage -Packages $references -ActionDescription 'restore locked' -ScriptBlock {
		Invoke-PullPackageWithRetry -PackageRef ([string]$Input) | Out-Null
	}
}

function Invoke-ToolchainVerify {
	[CmdletBinding()]
	param(
		[string[]]$Packages,
		[switch]$Json
	)
	if (-not $Packages) { $Packages = GetConfigPackages }
	if (-not $Packages) { throw 'no packages provided' }
	$results = foreach ($reference in $Packages) {
		$package = $reference | AsPackage
		$remoteRef = ResolveDockerRef -Pkg $package
		$root = GetVerifiedManifestResponse -Ref $remoteRef
		try {
			$rootDigest = GetDigest -Resp $root
			$rootManifest = $root | GetJsonResponse
		} finally { $root.Dispose() }
		$selected = GetResolvedManifestResponse -Ref $remoteRef
		try { $selectedDigest = GetDigest -Resp $selected } finally { $selected.Dispose() }
		$hostName = ([Uri](GetRegistryBaseUrl)).Host
		$refs = @("$hostName/$(GetRegistryRepoName)@$rootDigest")
		if ($selectedDigest -ne $rootDigest) { $refs += "$hostName/$(GetRegistryRepoName)@$selectedDigest" }
		foreach ($digestRef in $refs) { Invoke-ToolchainCosignVerify -RepoDigestRef $digestRef -Force }
		[pscustomobject]@{
			PSTypeName = 'Toolchain.VerificationResult'
			Package = [string]$package.Package
			Version = [string]$package.Version
			IndexDigest = if ($rootManifest.manifests) { $rootDigest } else { $null }
			Digest = $selectedDigest
			Verified = $true
		}
	}
	if ($Json) { return ($results | ConvertTo-Json -Depth 10) }
	return $results
}
