<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function New-ToolchainAuditFinding {
	param(
		[Parameter(Mandatory)][ValidateSet('Error','Warning')][string]$Severity,
		[Parameter(Mandatory)][string]$Category,
		[Parameter(Mandatory)][string]$Message
	)
	return [pscustomobject]@{
		Severity = $Severity
		Category = $Category
		Message = $Message
	}
}

function Get-ToolchainAuditReferenceName {
	param([Parameter(Mandatory)][string]$Reference)
	try { return [string](($Reference | AsPackage).Package) }
	catch { throw "invalid project package reference '$Reference': $($_.Exception.Message)" }
}

function Get-ToolchainAuditPolicyResult {
	param(
		[Parameter(Mandatory)][string]$Package,
		[string]$Version,
		[string]$Tag,
		[string]$Digest
	)
	try {
		$policy = GetToolchainPolicy
		$allowed, $reason = Test-ToolchainPolicyAllowsRegistry `
			-Policy $policy `
			-RegistryBaseUrl (GetRegistryBaseUrl) `
			-Repository (GetRegistryRepoName)
		if ($allowed) {
			$allowed, $reason = Test-ToolchainPolicyAllowsPackage `
				-Policy $policy `
				-Package $Package `
				-Version $Version `
				-Tag $Tag `
				-Digest $Digest
		}
		return [pscustomobject]@{
			Status = if ($allowed) { 'Allowed' } else { 'Denied' }
			Reason = [string]$reason
		}
	} catch {
		return [pscustomobject]@{ Status = 'Error'; Reason = [string]$_.Exception.Message }
	}
}

function Get-ToolchainAuditPackageResult {
	param(
		[Parameter(Mandatory)][string]$Name,
		[string]$ProjectReference,
		$LockEntry,
		[switch]$Refresh,
		[switch]$VerifySignatures
	)

	$findings = [Collections.Generic.List[object]]::new()
	$reference = if ($ProjectReference) {
		$ProjectReference
	} elseif ($LockEntry -and $LockEntry.reference) {
		[string]$LockEntry.reference
	} elseif ($LockEntry -and $LockEntry.digest) {
		"$Name@$([string]$LockEntry.digest)"
	} else {
		"${Name}:latest"
	}
	$package = $reference | AsPackage
	$lockedDigest = if ($LockEntry) { [string]$LockEntry.digest } else { '' }
	$installedDigest = [string]($package | ResolvePackageDigest)
	$remoteDigest = ''
	$remoteVersion = ''
	$remoteStatus = 'Available'
	try {
		$remote = Get-ToolchainRemotePackageLockEntry -Reference $reference
		$remoteDigest = [string]$remote.digest
		$remoteVersion = [string]$remote.version
	} catch {
		$remoteStatus = 'Error'
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Remote -Message $_.Exception.Message))
	}

	$lockStatus = 'Current'
	if (-not $LockEntry) {
		$lockStatus = 'Missing'
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message 'Package is missing from Toolchain.lock.json.'))
	} elseif (-not $ProjectReference) {
		$lockStatus = 'Orphaned'
		$findings.Add((New-ToolchainAuditFinding -Severity Warning -Category Lock -Message 'Lock entry is not present in Toolchain.ps1.'))
	} elseif ($LockEntry.reference -and [string]$LockEntry.reference -cne $ProjectReference) {
		$lockStatus = 'ReferenceDrift'
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message "Project reference '$ProjectReference' differs from locked reference '$([string]$LockEntry.reference)'."))
	} elseif ($lockedDigest -and $installedDigest -and $lockedDigest -ine $installedDigest) {
		$lockStatus = 'InstalledDrift'
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message 'Installed digest differs from the lock file.'))
	}

	$updateAvailable = [bool]($remoteDigest -and (($lockedDigest -and $remoteDigest -ine $lockedDigest) -or (-not $lockedDigest -and $installedDigest -and $remoteDigest -ine $installedDigest)))
	if ($updateAvailable) {
		if ($lockStatus -eq 'Current') { $lockStatus = 'UpdateAvailable' }
		$findings.Add((New-ToolchainAuditFinding -Severity Warning -Category Update -Message 'The project reference resolves to a newer digest.'))
	}
	if (-not $installedDigest) {
		$findings.Add((New-ToolchainAuditFinding -Severity Warning -Category Install -Message 'Package is not installed for the project reference.'))
	}

	$healthState = 'Unknown'
	$healthReason = ''
	try {
		$health = @(Get-ToolchainPackageHealth -Package $Name -Refresh:$Refresh | Select-Object -First 1)
		if ($health.Count -gt 0) {
			$healthState = [string]$health[0].State
			$healthReason = [string]$health[0].Reason
			if ($healthState -ine 'available') {
				$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Health -Message $(if ($healthReason) { $healthReason } else { "Package health is $healthState." })))
			}
		}
	} catch {
		$healthState = 'Error'
		$healthReason = [string]$_.Exception.Message
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Health -Message $healthReason))
	}

	$policy = Get-ToolchainAuditPolicyResult `
		-Package $Name `
		-Version $(if ($remoteVersion) { $remoteVersion } elseif ($LockEntry) { [string]$LockEntry.version } else { '' }) `
		-Tag ($package.Tag | AsTagString) `
		-Digest $(if ($remoteDigest) { $remoteDigest } else { $lockedDigest })
	if ($policy.Status -ne 'Allowed') {
		$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Policy -Message $(if ($policy.Reason) { $policy.Reason } else { "Policy status is $($policy.Status)." })))
	}

	$signatureStatus = 'NotRequired'
	$signatureReason = ''
	$signatureRequired = [bool](Get-ToolchainCosignVerifyEnabled)
	if ($VerifySignatures -or $signatureRequired) {
		$digestToVerify = if ($remoteDigest) { $remoteDigest } else { $lockedDigest }
		if (-not $digestToVerify) {
			$signatureStatus = 'Unavailable'
			$signatureReason = 'No canonical digest is available for signature verification.'
			$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Signature -Message $signatureReason))
		} elseif (GetToolchainRepo) {
			$signatureStatus = 'Offline'
			$signatureReason = 'Online Cosign verification is unavailable while an offline repository is active.'
			if ($signatureRequired) {
				$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Signature -Message $signatureReason))
			}
		} else {
			try {
				$null = Invoke-ToolchainVerify -Packages @("$Name@$digestToVerify")
				$signatureStatus = 'Verified'
			} catch {
				$signatureStatus = 'Failed'
				$signatureReason = [string]$_.Exception.Message
				$findings.Add((New-ToolchainAuditFinding -Severity Error -Category Signature -Message $signatureReason))
			}
		}
	}

	return [pscustomobject]@{
		PSTypeName = 'Toolchain.PackageAudit'
		Name = $Name
		Reference = $reference
		LockedDigest = $lockedDigest
		InstalledDigest = $installedDigest
		RemoteDigest = $remoteDigest
		RemoteVersion = $remoteVersion
		RemoteStatus = $remoteStatus
		LockStatus = $lockStatus
		UpdateAvailable = $updateAvailable
		HealthState = $healthState
		HealthReason = $healthReason
		SignatureStatus = $signatureStatus
		SignatureReason = $signatureReason
		PolicyStatus = [string]$policy.Status
		PolicyReason = [string]$policy.Reason
		Findings = @($findings)
	}
}

function Invoke-ToolchainAudit {
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
	param(
		[string]$Path,
		[switch]$Refresh,
		[switch]$VerifySignatures,
		[switch]$Fix,
		[switch]$Strict,
		[switch]$Json
	)

	$lockPath = Get-ToolchainLockPath -Path $Path
	$globalFindings = [Collections.Generic.List[object]]::new()
	$lockDocument = $null
	if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
		try { $lockDocument = Read-ToolchainLock -Path $lockPath }
		catch { $globalFindings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message $_.Exception.Message)) }
	} else {
		$globalFindings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message "Toolchain lock file not found: $lockPath"))
	}

	$projectReferences = @(GetConfigPackages)
	$projectByName = @{}
	foreach ($reference in $projectReferences) {
		$name = Get-ToolchainAuditReferenceName -Reference ([string]$reference)
		if ($projectByName.ContainsKey($name)) {
			$globalFindings.Add((New-ToolchainAuditFinding -Severity Error -Category Project -Message "Duplicate Toolchain project package reference: $name"))
			continue
		}
		$projectByName[$name] = [string]$reference
	}

	$lockByName = @{}
	if ($lockDocument) {
		foreach ($entry in @($lockDocument.packages)) {
			$name = [string]$entry.package
			if ($lockByName.ContainsKey($name)) {
				$globalFindings.Add((New-ToolchainAuditFinding -Severity Error -Category Lock -Message "Duplicate lock entry: $name"))
				continue
			}
			$lockByName[$name] = $entry
		}
	}

	$names = @($projectByName.Keys) + @($lockByName.Keys | Where-Object { -not $projectByName.ContainsKey($_) })
	$packages = foreach ($name in @($names | Sort-Object -Unique)) {
		Get-ToolchainAuditPackageResult `
			-Name ([string]$name) `
			-ProjectReference $(if ($projectByName.ContainsKey($name)) { [string]$projectByName[$name] } else { $null }) `
			-LockEntry $(if ($lockByName.ContainsKey($name)) { $lockByName[$name] } else { $null }) `
			-Refresh:$Refresh `
			-VerifySignatures:$VerifySignatures
	}
	$allFindings = @($globalFindings) + @($packages | ForEach-Object { @($_.Findings) })
	$problemCount = @($allFindings).Count
	$report = [pscustomobject]@{
		PSTypeName = 'Toolchain.AuditReport'
		GeneratedAt = [datetime]::UtcNow
		LockPath = $lockPath
		LockPresent = [bool]$lockDocument
		HasProblems = ($problemCount -gt 0)
		Summary = [pscustomobject]@{
			Packages = @($packages).Count
			Problems = $problemCount
			Errors = @($allFindings | Where-Object Severity -eq Error).Count
			Warnings = @($allFindings | Where-Object Severity -eq Warning).Count
			Updates = @($packages | Where-Object UpdateAvailable).Count
			PolicyViolations = @($packages | Where-Object PolicyStatus -in @('Denied','Error')).Count
			SignatureFailures = @($packages | Where-Object SignatureStatus -in @('Failed','Unavailable')).Count
			HealthProblems = @($packages | Where-Object HealthState -notin @('available','Available')).Count
		}
		Findings = @($globalFindings)
		Packages = @($packages)
		Remediation = [pscustomobject]@{
			Requested = [bool]$Fix
			Applied = $false
			Changed = $false
			Actions = @()
		}
	}

	if ($Fix) {
		$actions = [Collections.Generic.List[string]]::new()
		$lockNeeded = (-not $lockDocument) -or [bool](@($packages | Where-Object {
			$_.LockStatus -in @('Missing','Orphaned','ReferenceDrift','UpdateAvailable') -or $_.UpdateAvailable
		}).Count)
		$restoreNeeded = $lockNeeded -or [bool](@($packages | Where-Object {
			-not $_.InstalledDigest -or $_.LockStatus -eq 'InstalledDrift'
		}).Count)
		if ($lockNeeded) { $actions.Add('RegenerateLock') }
		if ($restoreNeeded) { $actions.Add('RestorePackages') }
		$report.Remediation.Actions = @($actions)

		$blockingFindings = @($allFindings | Where-Object { $_.Category -notin @('Lock','Install','Update') })
		if ($projectReferences.Count -eq 0) {
			$blockingFindings += New-ToolchainAuditFinding -Severity Error -Category Project -Message 'Toolchain project has no package references to lock and restore.'
		}
		if ($blockingFindings.Count -gt 0) {
			$output = if ($Json) { $report | ConvertTo-Json -Depth 20 } else { $report }
			Write-Output $output
			$categories = @($blockingFindings.Category | Sort-Object -Unique) -join ', '
			throw "Toolchain audit cannot safely fix state while blocking findings remain: $categories."
		}

		if ($actions.Count -eq 0) {
			$report.Remediation.Applied = $true
		} elseif ($PSCmdlet.ShouldProcess($lockPath, 'regenerate the Toolchain lock and restore its packages')) {
			if ($lockNeeded) {
				$null = Invoke-ToolchainLock -Packages $projectReferences -Path $lockPath
			}
			if ($restoreNeeded) {
				$null = Invoke-ToolchainRestore -Path $lockPath
			}
			$report = Invoke-ToolchainAudit -Path $lockPath -Refresh:$Refresh -VerifySignatures:$VerifySignatures
			$report.Remediation.Requested = $true
			$report.Remediation.Applied = $true
			$report.Remediation.Changed = $true
			$report.Remediation.Actions = @($actions)
		}
	}

	$output = if ($Json) { $report | ConvertTo-Json -Depth 20 } else { $report }
	if ($Strict -and $report.HasProblems) {
		Write-Output $output
		throw "Toolchain audit found $problemCount problem(s)."
	}
	return $output
}
