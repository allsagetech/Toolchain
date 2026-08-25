<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function AsDockerPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$RegistryTag
	)

	if ($RegistryTag -match '^(.*)-([0-9].+)$') {
		return @{
			Package = $Matches[1]
			Tag     = $Matches[2] | AsTagHashtable
		}
	}

	$repo = (GetRegistryRepoName)
	$pkg  = ($repo -split '/')[-1]

	return @{
		Package = $pkg
		Tag     = $RegistryTag | AsTagHashtable
	}
}

function AsTagHashtable {
	param (
		[Parameter(ValueFromPipeline)]
		[string]$Tag
	)

	if ($Tag -in 'latest', '', $null) {
		return @{ Latest = $true }
	}

	$semverCandidate = $Tag
	if ($semverCandidate -match '^v(.*)$') {
		$semverCandidate = $Matches[1]
	}

	if ($semverCandidate -match '^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:(?:\+|_)([0-9]+))?$') {
		return @{
			Major = $Matches[1]
			Minor = $Matches[2]
			Patch = $Matches[3]
			Build = $Matches[4]
		}
	}

	return @{ Raw = $Tag }
}

function AsTagString {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[collections.Hashtable]$Tag
	)

	if ($true -eq $Tag.Latest) {
		return "latest"
	}

	if ($Tag.ContainsKey('Raw') -and $Tag.Raw) {
		return "$($Tag.Raw)"
	}

	$s = "$($Tag.Major)"
	if ($Tag.Minor) { $s += ".$($Tag.Minor)" }
	if ($Tag.Patch) { $s += ".$($Tag.Patch)" }
	if ($Tag.Build) { $s += "+$($Tag.Build)" }
	return $s
}

function Test-ToolchainRegistryMetadataTag {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Tag
	)

	# Cosign stores signatures and attestations as tags alongside package tags.
	# Release SBOMs, package-kind markers, and temporary release-staging tags
	# are also registry metadata. None of these are installable packages.
	return ($Tag -match '(?i)^sha256-[0-9a-f]{64}\.(sig|att|sbom)$') -or
		($Tag -match '(?i)^sbom-v[0-9]+-[a-z0-9][a-z0-9._-]*$') -or
		($Tag -match '(?i)^tlc-kind-[a-z0-9-]+--[a-z0-9][a-z0-9._-]*$') -or
		($Tag -match '(?i)^tlc-catalog-v[0-9]+$') -or
		($Tag -match '(?i)^tlc-platform-[a-z0-9._-]+$') -or
		($Tag -match '(?i)^staging-[a-z0-9][a-z0-9._-]*$')
}

function GetCompleteRemoteModelCatalog {
	param (
		[string[]]$Tags
	)

	$generations = @{}
	foreach ($tag in @($Tags)) {
		if ($tag -notmatch '(?i)^tlc-kind-model-v1-([0-9]+)-([0-9]+)--([a-z0-9][a-z0-9._-]*)$') {
			continue
		}

		$generation = [UInt64]0
		$count = 0
		if (-not [UInt64]::TryParse([string]$Matches[1], [ref]$generation) -or
			-not [int]::TryParse([string]$Matches[2], [ref]$count) -or
			$count -lt 0 -or $count -gt 10000) {
			continue
		}

		$key = $generation.ToString()
		if (-not $generations.ContainsKey($key)) {
			$generations[$key] = @{
				Generation = $generation
				Counts = @{}
				Packages = @{}
				ExactPackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
				FoldedPackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
				MarkerCount = 0
				EmptySentinelCount = 0
				Invalid = $false
			}
		}

		$entry = $generations[$key]
		$entry.MarkerCount += 1
		$entry.Counts[[string]$count] = $true
		$package = [string]$Matches[3]
		if ($count -eq 0) {
			if ($package -ceq 'empty') {
				$entry.EmptySentinelCount += 1
			} else {
				$entry.Invalid = $true
			}
		} else {
			$null = $entry.ExactPackages.Add($package)
			$null = $entry.FoldedPackages.Add($package)
			$entry.Packages[$package.ToLowerInvariant()] = $package
		}
	}

	$complete = foreach ($entry in $generations.Values) {
		if ($entry.Invalid -or $entry.Counts.Count -ne 1) { continue }
		$expectedCount = [int]@($entry.Counts.Keys)[0]
		if ($expectedCount -eq 0) {
			if ($entry.MarkerCount -ne 1 -or $entry.EmptySentinelCount -ne 1 -or $entry.Packages.Count -ne 0) { continue }
		} elseif ($entry.EmptySentinelCount -ne 0 -or
			$entry.MarkerCount -ne $expectedCount -or
			$entry.ExactPackages.Count -ne $expectedCount -or
			$entry.FoldedPackages.Count -ne $expectedCount) {
			continue
		}
		$entry
	}

	$selected = @($complete | Sort-Object -Property Generation -Descending | Select-Object -First 1)
	if ($selected.Count -eq 0) {
		return [pscustomobject]@{ Found = $false; Packages = @() }
	}

	return [pscustomobject]@{
		Found = $true
		Generation = $selected[0].Generation
		Packages = @($selected[0].Packages.Values | Sort-Object)
	}
}

function GetRemotePackageKinds {
	param (
		[string[]]$Tags
	)

	$kinds = @{}
	$catalog = GetCompleteRemoteModelCatalog -Tags $Tags
	$hasAuthoritativeCatalog = [bool]$catalog.Found
	if ($hasAuthoritativeCatalog) {
		foreach ($package in @($catalog.Packages)) {
			$kinds[[string]$package] = 'model'
		}
	} else {
		foreach ($tag in @($Tags)) {
			if ($tag -match '(?i)^tlc-kind-model--([a-z0-9][a-z0-9._-]*)$') {
				$kinds[[string]$Matches[1]] = 'model'
			}
		}
	}

	# The official repository predates package-kind markers. Keep this explicit
	# migration catalog only until its first complete marker catalog is
	# published. Complete generations are authoritative, so partial registry
	# propagation cannot expose a half-updated classification.
	if (-not $hasAuthoritativeCatalog -and $kinds.Count -eq 0 -and (GetRegistryRepoName) -ieq 'allsagetech/toolchains') {
		foreach ($package in @(
			'openai-gpt-oss-20b',
			'qwen2.5-0.5b-instruct',
			'qwen2.5-coder-7b-instruct',
			'qwen3-0.6b',
			'smollm2-135m-instruct',
			'smollm2-360m-instruct'
		)) {
			$kinds[$package] = 'model'
		}
	}

	# Custom and legacy registries can opt in without changing tag publication.
	foreach ($package in @(([string]$env:TOOLCHAIN_MODEL_PACKAGES) -split '[,;\s]+' | Where-Object { $_ })) {
		$kinds[[string]$package] = 'model'
	}

	return $kinds
}

function GetRemotePlatformAliases {
	param([string[]]$Tags)
	$aliases = @{}
	foreach ($tag in @($Tags)) {
		if ($tag -match '(?i)^tlc-kind-platform-v1--([a-z0-9][a-z0-9._-]*)--([a-z0-9][a-z0-9._-]*)$') {
			$aliases[[string]$Matches[1]] = [string]$Matches[2]
		}
	}
	return $aliases
}

function GetDockerPackages {
	param (
		[ValidateSet('All', 'Tooling', 'Model')]
		[string]$Kind = 'All',
		[ref]$KindsOutput,
		[ref]$AliasesOutput,
		[switch]$Refresh
	)

	$tags = @((GetTagsList -Refresh:$Refresh).Tags)
	$kindMap = GetRemotePackageKinds -Tags $tags
	$aliasMap = GetRemotePlatformAliases -Tags $tags
	if ($PSBoundParameters.ContainsKey('KindsOutput')) {
		$KindsOutput.Value = $kindMap
	}
	if ($PSBoundParameters.ContainsKey('AliasesOutput')) { $AliasesOutput.Value = $aliasMap }
	$docker = @{}
	foreach ($tag in $tags) {
		if ($tag | Test-ToolchainRegistryMetadataTag) {
			continue
		}
		$pkg = $tag | AsDockerPackage
		$isModel = $kindMap.ContainsKey([string]$pkg.Package) -and $kindMap[[string]$pkg.Package] -eq 'model'
		if (($Kind -eq 'Tooling' -and $isModel) -or ($Kind -eq 'Model' -and -not $isModel)) {
			continue
		}
		$docker.$($pkg.Package) = $docker.$($pkg.Package) + @($pkg.Tag)
	}
	$docker
}

function GetDockerTags {
	param (
		[ValidateSet('All', 'Tooling', 'Model')]
		[string]$Kind = 'All',
		[switch]$ToolingDefaultDisplay,
		[switch]$SkipHealthPolicy,
		[switch]$Refresh
	)

	$packageKinds = $null
	$platformAliases = $null
	if ($ToolingDefaultDisplay) {
		$docker = GetDockerPackages -Kind All -KindsOutput ([ref]$packageKinds) -AliasesOutput ([ref]$platformAliases) -Refresh:$Refresh
	} else {
		$docker = GetDockerPackages -Kind $Kind -Refresh:$Refresh
	}
	if (-not $SkipHealthPolicy -and (Get-Command Protect-ToolchainRemoteCatalogWithHealthPolicy -ErrorAction SilentlyContinue)) {
		$docker = Protect-ToolchainRemoteCatalogWithHealthPolicy -Catalog $docker -Refresh:$Refresh
	}
	$o = New-Object PSObject
	foreach ($k in $docker.keys | Sort-Object) {
		$arr = @()
		foreach ($t in $docker.$k) {
			$arr += [Tag]::new(($t | AsTagString))
		}
		$o | Add-Member -MemberType NoteProperty -Name $k -Value ($arr | Sort-Object -Descending)
	}
	if ($ToolingDefaultDisplay) {
		$toolingProperties = [string[]]@($docker.Keys | Where-Object {
			-not ($packageKinds.ContainsKey([string]$_) -and $packageKinds[[string]$_] -eq 'model') -and
			-not $platformAliases.ContainsKey([string]$_)
		} | Sort-Object)
		if ($toolingProperties.Count -eq 0) {
			# An empty default display set makes PowerShell fall back to every
			# property, which would reveal the model-only catalog. Use a status
			# property whose name cannot collide with a valid package name.
			$o | Add-Member -MemberType NoteProperty -Name 'Tooling packages' -Value 'None'
			$toolingProperties = [string[]]@('Tooling packages')
		}
		$displaySet = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet', $toolingProperties)
		$standardMembers = [System.Management.Automation.PSMemberSet]::new(
			'PSStandardMembers',
			[System.Management.Automation.PSMemberInfo[]]@($displaySet)
		)
		$o.PSObject.Members.Add($standardMembers)
	}
	$o
}

function GetRemoteRegistryTags {
	param([switch]$Refresh)
	@((GetTagsList -Refresh:$Refresh).Tags) | Sort-Object
}
