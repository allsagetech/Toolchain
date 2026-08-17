<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainActivation = $null

function Get-ToolchainEnvironmentSnapshot {
	$snapshot = @{}
	foreach ($entry in Get-ToolchainEnvironmentItems) {
		$snapshot[$entry.Name.ToUpperInvariant()] = [pscustomobject]@{
			Name = [string]$entry.Name
			Value = [string]$entry.Value
		}
	}
	return $snapshot
}

function Get-ToolchainEnvironmentChanges {
	param(
		[Parameter(Mandatory)][hashtable]$Before,
		[Parameter(Mandatory)][hashtable]$After
	)
	$changes = @()
	$keys = @($Before.Keys) + @($After.Keys) | Sort-Object -Unique
	foreach ($key in $keys) {
		$beforeEntry = if ($Before.ContainsKey($key)) { $Before[$key] } else { $null }
		$afterEntry = if ($After.ContainsKey($key)) { $After[$key] } else { $null }
		$beforeValue = if ($beforeEntry) { [string]$beforeEntry.Value } else { $null }
		$afterValue = if ($afterEntry) { [string]$afterEntry.Value } else { $null }
		if (($null -eq $beforeEntry) -ne ($null -eq $afterEntry) -or -not [string]::Equals($beforeValue, $afterValue, [StringComparison]::Ordinal)) {
			$changes += [pscustomobject]@{
				Name = if ($beforeEntry) { [string]$beforeEntry.Name } elseif ($afterEntry) { [string]$afterEntry.Name } else { [string]$key }
				Existed = ($null -ne $beforeEntry)
				Value = $beforeValue
			}
		}
	}
	return @($changes)
}

function Restore-ToolchainEnvironmentChanges {
	param([Parameter(Mandatory)][object[]]$Changes)
	foreach ($change in $Changes) {
		$value = if ($change.Existed) { [string]$change.Value } else { $null }
		Set-ToolchainEnvironmentValue -Name ([string]$change.Name) -Value $value
	}
}

function Test-ToolchainLockMatchesProject {
	param(
		[Parameter(Mandatory)][object]$Lock,
		[Parameter(Mandatory)][object]$Project
	)
	if (-not $Lock.projectDigest -or [string]$Lock.projectDigest -ne [string]$Project.Digest) { return $false }
	if ([string]$Lock.registry -ne [string](GetRegistryBaseUrl) -or [string]$Lock.repository -ne [string](GetRegistryRepoName)) { return $false }
	$expectedPlatform = "$(GetRegistryPlatformOs)/$(GetRegistryPlatformArch)"
	if (@($Lock.packages).Count -ne @($Project.PackageNames).Count) { return $false }
	$expectedNames = @($Project.PackageNames | Sort-Object -Unique)
	$lockedNames = @($Lock.packages | ForEach-Object { [string]$_.package } | Sort-Object -Unique)
	if ($expectedNames.Count -ne $lockedNames.Count) { return $false }
	for ($index = 0; $index -lt $expectedNames.Count; $index++) {
		if (-not [string]::Equals($expectedNames[$index], $lockedNames[$index], [StringComparison]::OrdinalIgnoreCase)) { return $false }
	}
	foreach ($entry in @($Lock.packages)) {
		if ([string]$entry.platform -ne $expectedPlatform) { return $false }
	}
	return $true
}

function Invoke-ToolchainSync {
	[CmdletBinding()]
	param(
		[string]$Path,
		[switch]$Update,
		[switch]$Frozen,
		[switch]$NoRestore,
		[switch]$Activate,
		[switch]$PassThru
	)
	$project = Read-ToolchainProject -NoResolve
	$lockPath = Get-ToolchainLockPath -Path $Path
	$lock = $null
	$usedExistingLock = $false
	if (-not $Update -and (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
		try {
			$candidate = Read-ToolchainLock -Path $lockPath
			if (Test-ToolchainLockMatchesProject -Lock $candidate -Project $project) {
				$lock = $candidate
				$usedExistingLock = $true
			}
		} catch {
			if ($Frozen) { throw }
			Write-Debug "Ignoring stale or invalid lock during sync: $($_.Exception.Message)"
		}
	}
	if (-not $lock) {
		if ($Frozen) { throw "Toolchain lock is missing or stale for $($project.Path); run 'tlc sync' without -Frozen to refresh it" }
		$project.Packages = @(Resolve-ToolchainProjectPackages -PackageSpecs $project.PackageSpecs)
		if (@($project.Packages | Where-Object { ([string]$_).StartsWith('file:///') }).Count -gt 0) {
			throw 'tlc sync cannot create an immutable lock for file:/// packages; publish the package by digest or use tlc activate -NoSync'
		}
		$lock = Invoke-ToolchainLock -Packages $project.Packages -Path $lockPath -ProjectDigest $project.Digest
	}
	if (-not $NoRestore) { $null = Invoke-ToolchainRestore -Path $lockPath }
	if ($Activate) { $null = Invoke-ToolchainActivate -Path $lockPath }
	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.SyncResult'
		Project = $project.Path
		LockPath = $lockPath
		ProjectDigest = $project.Digest
		Packages = @($lock.packages).Count
		UsedExistingLock = $usedExistingLock
		Restored = (-not $NoRestore)
		Activated = [bool]$Activate
	}
	if ($PassThru) { return $result }
	Write-ToolchainInfo "Synchronized $($result.Packages) package(s) from $($project.Path)"
}

function Invoke-ToolchainActivate {
	[CmdletBinding()]
	param(
		[string]$Path,
		[switch]$NoSync,
		[switch]$PassThru
	)
	$project = Read-ToolchainProject -NoResolve
	if ($script:ToolchainActivation) {
		if ([string]::Equals([string]$script:ToolchainActivation.Project, [string]$project.Path, [StringComparison]::OrdinalIgnoreCase)) {
			Write-ToolchainInfo "Toolchain environment is already active: $($project.Path)"
			if ($PassThru) { return $script:ToolchainActivation }
			return
		}
		throw "another Toolchain environment is active: $($script:ToolchainActivation.Project); run 'tlc deactivate' first"
	}
	if (-not $NoSync) {
		$null = Invoke-ToolchainSync -Path $Path
		$lock = Read-ToolchainLock -Path $Path
		$packages = @($lock.packages | ForEach-Object {
			$configuration = if ($_.configuration) { [string]$_.configuration } else { 'default' }
			"$($_.package)@$($_.digest)::$($configuration)"
		})
	} else {
		$packages = @(Resolve-ToolchainProjectPackages -PackageSpecs $project.PackageSpecs)
	}
	$before = Get-ToolchainEnvironmentSnapshot
	try {
		Invoke-ToolchainLoad -Packages $packages
		Set-ToolchainEnvironmentValue -Name 'TOOLCHAIN_ACTIVE_PROJECT' -Value $project.Path
		$after = Get-ToolchainEnvironmentSnapshot
		$changes = Get-ToolchainEnvironmentChanges -Before $before -After $after
		$script:ToolchainActivation = [pscustomobject]@{
			PSTypeName = 'Toolchain.Activation'
			Project = $project.Path
			ActivatedAt = [datetime]::UtcNow
			Packages = @($packages)
			EnvironmentChanges = @($changes)
		}
	} catch {
		$afterFailure = Get-ToolchainEnvironmentSnapshot
		$changes = Get-ToolchainEnvironmentChanges -Before $before -After $afterFailure
		Restore-ToolchainEnvironmentChanges -Changes $changes
		throw
	}
	Write-ToolchainInfo "Activated Toolchain environment: $($project.Path)"
	if ($PassThru) { return $script:ToolchainActivation }
}

function Invoke-ToolchainDeactivate {
	[CmdletBinding()]
	param([switch]$PassThru)
	if (-not $script:ToolchainActivation) {
		Write-ToolchainInfo 'No Toolchain environment is active.'
		return
	}
	$activation = $script:ToolchainActivation
	Restore-ToolchainEnvironmentChanges -Changes @($activation.EnvironmentChanges)
	$script:ToolchainActivation = $null
	Write-ToolchainInfo "Deactivated Toolchain environment: $($activation.Project)"
	if ($PassThru) { return $activation }
}
