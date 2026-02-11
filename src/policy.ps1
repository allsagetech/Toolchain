<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\config.ps1

$script:ToolchainPolicyCache = $null
$script:ToolchainPolicyCachePath = $null

function GetToolchainPolicyPath {
	if ($ToolchainPolicyPath) { return $ToolchainPolicyPath }
	if ($env:ToolchainPolicyPath) { return $env:ToolchainPolicyPath }
	if ($env:TOOLCHAIN_POLICY_PATH) { return $env:TOOLCHAIN_POLICY_PATH }

	$cfg = FindConfig
	$base = if ($cfg) { Split-Path -Parent $cfg } else { (Get-Location).Path }
	return (Join-Path $base 'Toolchain.policy.json')
}

function GetToolchainPolicy {
	$path = GetToolchainPolicyPath
	if (-not $path) { return $null }
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }

	if ($script:ToolchainPolicyCache -and ($script:ToolchainPolicyCachePath -eq $path)) {
		return $script:ToolchainPolicyCache
	}

	try {
		$obj = (Get-Content -LiteralPath $path -Raw) | ConvertFrom-Json
		$policy = ($obj | ConvertTo-HashTable)
		$script:ToolchainPolicyCache = $policy
		$script:ToolchainPolicyCachePath = $path
		return $policy
	} catch {
		throw "Failed to parse policy JSON at '$path': $_"
	}
}

function Test-TruthyValue {
	param([string]$Value)
	if ($null -eq $Value) { return $false }
	$v = ([string]$Value).Trim()
	if ($v -eq '') { return $false }
	$v = $v.ToLowerInvariant()
	if ($v -in @('0','false','no','off','n','f')) { return $false }
	return $true
}

function ConvertTo-ToolchainVersionString {
	param([string]$Version)
	if (-not $Version) { return $null }
	$Version = [string]$Version
	if ($Version -match '^v(.+)$') { $Version = $Matches[1] }
	return ($Version.Replace('_','+'))
}

function ConvertTo-ToolchainVersionTuple {
	param([string]$Version)
	$Version = ConvertTo-ToolchainVersionString $Version
	if (-not $Version) { return $null }
	if ($Version -match '^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:\+[0-9]+)?$') {
		$maj = [int]$Matches[1]
		$min = if ($Matches[2]) { [int]$Matches[2] } else { 0 }
		$pat = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
		return @($maj,$min,$pat)
	}
	throw "invalid version: $Version"
}

function Compare-ToolchainVersionTuple {
	param(
		[Parameter(Mandatory)][int[]]$A,
		[Parameter(Mandatory)][int[]]$B
	)
	for ($i = 0; $i -lt 3; $i++) {
		if ($A[$i] -lt $B[$i]) { return -1 }
		if ($A[$i] -gt $B[$i]) { return 1 }
	}
	return 0
}

function Test-ToolchainComparator {
	param(
		[Parameter(Mandatory)][string]$Left,
		[Parameter(Mandatory)][string]$Op,
		[Parameter(Mandatory)][string]$Right
	)
	$lt = ConvertTo-ToolchainVersionTuple $Left
	$rt = ConvertTo-ToolchainVersionTuple $Right
	if (-not $lt -or -not $rt) { return $false }
	$cmp = Compare-ToolchainVersionTuple -A $lt -B $rt
	switch ($Op) {
		'>'  { return ($cmp -gt 0) }
		'>=' { return ($cmp -ge 0) }
		'<'  { return ($cmp -lt 0) }
		'<=' { return ($cmp -le 0) }
		'='  { return ($cmp -eq 0) }
		default { return $false }
	}
}

function Test-ToolchainConstraintMatch {
	param(
		[Parameter(Mandatory)][string]$Constraint,
		[string]$Version,
		[string]$Tag,
		[string]$Digest
	)
	$Constraint = [string]$Constraint
	if ($Constraint -eq '*' -or $Constraint -eq '') { return $true }

	$ver = ConvertTo-ToolchainVersionString $Version
	$tag = ConvertTo-ToolchainVersionString $Tag

	if ($Constraint -eq 'latest') {
		return ($tag -eq 'latest')
	}

	if ($Constraint -match '^sha256:[0-9a-fA-F]{64}$') {
		return ($Digest -and ($Digest -ieq $Constraint))
	}

	if ($Constraint -like '*`**') {
		$pattern = ConvertTo-ToolchainVersionString $Constraint
		if ($ver -and ($ver -like $pattern)) { return $true }
		if ($tag -and ($tag -like $pattern)) { return $true }
		return $false
	}

	if ($Constraint -match '^(>=|<=|>|<|=)') {
		$parts = $Constraint -split '\s+'
		foreach ($p in $parts) {
			if (-not $p) { continue }
			if ($p -match '^(>=|<=|>|<|=)(.+)$') {
				$op = $Matches[1]
				$rhs = $Matches[2].Trim()
				$lhs = if ($ver) { $ver } else { $tag }
				if (-not (Test-ToolchainComparator -Left $lhs -Op $op -Right $rhs)) { return $false }
			} else {
				return $false
			}
		}
		return $true
	}

	$want = ConvertTo-ToolchainVersionString $Constraint
	if ($ver -and ($ver -ieq $want)) { return $true }
	if ($tag -and ($tag -ieq $want)) { return $true }
	return $false
}

function Test-ToolchainPolicyAllowsRegistry {
	param(
		[hashtable]$Policy,
		[string]$RegistryBaseUrl,
		[string]$Repository
	)
	if (-not $Policy) { return $true, $null }

	if ($Policy.allowedRegistries -and $RegistryBaseUrl) {
		$registryHost = $null
		try {
			$u = [Uri]::new($RegistryBaseUrl)
			$registryHost = $u.Host
		} catch {
			$registryHost = $RegistryBaseUrl
		}
		$ok = $false
		foreach ($r in $Policy.allowedRegistries) {
			if (-not $r) { continue }
			$rHost = $null
			try { $rHost = ([Uri]::new([string]$r)).Host } catch { $rHost = [string]$r }
			if ($registryHost -ieq $rHost -or $RegistryBaseUrl.TrimEnd('/') -ieq ([string]$r).TrimEnd('/')) { $ok = $true; break }
		}
		if (-not $ok) { return $false, "registry not allowed by policy: $RegistryBaseUrl" }
	}

	if ($Policy.allowedRepositories -and $Repository) {
		$ok = $false
		foreach ($p in $Policy.allowedRepositories) {
			if ($Repository -ieq [string]$p) { $ok = $true; break }
		}
		if (-not $ok) { return $false, "repository not allowed by policy: $Repository" }
	}

	return $true, $null
}

function Test-ToolchainPolicyAllowsPackage {
	param(
		[hashtable]$Policy,
		[Parameter(Mandatory)][string]$Package,
		[string]$Version,
		[string]$Tag,
		[string]$Digest
	)

	if (-not $Policy) { return $true, $null }

	$default = if ($Policy.defaultAction) { ([string]$Policy.defaultAction).ToLowerInvariant() } else { 'allow' }
	$rules = $null
	if ($Policy.packages) {
		try { $rules = $Policy.packages[$Package] } catch { $rules = $null }
	}

	$denyList = $null
	$allowList = $null
	if ($rules) {
		$denyList = $rules.deny
		$allowList = $rules.allow
	}

	if ($denyList) {
		foreach ($c in @($denyList)) {
			if (Test-ToolchainConstraintMatch -Constraint ([string]$c) -Version $Version -Tag $Tag -Digest $Digest) {
				return $false, "denied by policy: $Package matches deny constraint '$c'"
			}
		}
	}

	if ($allowList) {
		foreach ($c in @($allowList)) {
			if (Test-ToolchainConstraintMatch -Constraint ([string]$c) -Version $Version -Tag $Tag -Digest $Digest) {
				return $true, $null
			}
		}
		return $false, "denied by policy: $Package did not match any allow constraints"
	}

	if ($default -eq 'deny') {
		return $false, "denied by policy: defaultAction=deny and $Package has no allow rules"
	}

	return $true, $null
}

function Assert-ToolchainPolicyAllowed {
	param(
		[Parameter(Mandatory)][string]$Action,
		[Parameter(Mandatory)][string]$Package,
		[string]$Version,
		[string]$Tag,
		[string]$Digest,
		[string]$RegistryBaseUrl,
		[string]$Repository
	)
	$policy = GetToolchainPolicy
	$ok, $reason = Test-ToolchainPolicyAllowsRegistry -Policy $policy -RegistryBaseUrl $RegistryBaseUrl -Repository $Repository
	if (-not $ok) { throw "Toolchain policy denied $Action for $($Package): $reason" }

	$ok, $reason = Test-ToolchainPolicyAllowsPackage -Policy $policy -Package $Package -Version $Version -Tag $Tag -Digest $Digest
	if (-not $ok) { throw "Toolchain policy denied $Action for $($Package): $reason" }
}

function Get-ToolchainPolicyRequireSignedManifest {
	$policy = GetToolchainPolicy
	if ($policy -and $policy.requireSignedManifests) { return $true }
	if (Test-TruthyValue $env:TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS) { return $true }
	return $false
}

function Get-ToolchainPolicyTrustedSigner {
	$policy = GetToolchainPolicy
	if ($policy -and $policy.trustedSigners) {
		return @($policy.trustedSigners | ForEach-Object { ([string]$_).Replace(' ','').ToUpperInvariant() })
	}
	return @()
}

function Get-ToolchainPolicyRequireCosign {
	$envVal = (Get-Item env:TOOLCHAIN_COSIGN_VERIFY -ErrorAction SilentlyContinue).Value
	if ($null -ne $envVal) {
		return (Test-TruthyValue $envVal)
	}

	$policy = GetToolchainPolicy
	if ($policy -and $policy.requireCosign) { return $true }
	return $false
}

function Get-ToolchainPolicyCosignKey {
	$envKey = (Get-Item env:TOOLCHAIN_COSIGN_KEY -ErrorAction SilentlyContinue).Value
	if ($envKey) { return [string]$envKey }

	$policy = GetToolchainPolicy
	if ($policy -and $policy.cosignKey) { return [string]$policy.cosignKey }
	return $null
}



Set-Alias -Name Normalize-ToolchainVersionString -Value ConvertTo-ToolchainVersionString
Set-Alias -Name Assert-ToolchainPolicyAllows -Value Assert-ToolchainPolicyAllowed
Set-Alias -Name Get-ToolchainPolicyRequireSignedManifests -Value Get-ToolchainPolicyRequireSignedManifest
Set-Alias -Name Get-ToolchainPolicyTrustedSigners -Value Get-ToolchainPolicyTrustedSigner
