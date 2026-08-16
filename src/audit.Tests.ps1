<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function AsTagString { param([Parameter(ValueFromPipeline)]$Tag) process { [string]$Tag } }
	function AsPackage {
		param([Parameter(ValueFromPipeline)]$Reference)
		process {
			$name = ([string]$Reference -split '[@:]')[0]
			@{ Package=$name; Tag='latest'; Version='latest'; Config='default' }
		}
	}
	function ResolvePackageDigest { param([Parameter(ValueFromPipeline)]$Package) process { $script:installedDigest } }
	function Get-ToolchainRemotePackageLockEntry { param($Reference) $script:remoteEntry }
	function Get-ToolchainPackageHealth { param($Package,[switch]$Refresh) $script:healthEntry }
	function GetToolchainPolicy { $script:policy }
	function Test-ToolchainPolicyAllowsRegistry { param($Policy,$RegistryBaseUrl,$Repository) $true,$null }
	function Test-ToolchainPolicyAllowsPackage { param($Policy,$Package,$Version,$Tag,$Digest) $true,$null }
	function GetRegistryBaseUrl { 'https://registry.example.test' }
	function GetRegistryRepoName { 'owner/toolchains' }
	function Get-ToolchainCosignVerifyEnabled { $script:signatureRequired }
	function GetToolchainRepo { $script:offlineRepo }
	function Invoke-ToolchainVerify { param($Packages) [pscustomobject]@{ Verified=$true } }
	function Get-ToolchainLockPath { param($Path) if ($Path) { $Path } else { Join-Path $TestDrive 'Toolchain.lock.json' } }
	function Read-ToolchainLock { param($Path) Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
	function GetConfigPackages { $script:projectPackages }
	function Invoke-ToolchainLock { param($Packages,$Path) }
	function Invoke-ToolchainRestore { param($Path) }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain project audit' {
	BeforeEach {
		$script:installedDigest = 'sha256:' + ('a' * 64)
		$script:remoteEntry = [pscustomobject]@{ digest=$script:installedDigest; version='1.0.0' }
		$script:healthEntry = [pscustomobject]@{ State='available'; Reason='' }
		$script:policy = $null
		$script:signatureRequired = $false
		$script:offlineRepo = $null
		$script:projectPackages = @('demo:latest')
	}

	It 'returns a clean report for a locked, installed, healthy package' {
		$path = Join-Path $TestDrive 'clean.json'
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1.0.0'; digest=$script:installedDigest }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		$report = Invoke-ToolchainAudit -Path $path
		$report.HasProblems | Should -BeFalse
		$report.Summary.Packages | Should -Be 1
		$report.Packages[0].LockStatus | Should -Be 'Current'
		$report.Packages[0].SignatureStatus | Should -Be 'NotRequired'
	}

	It 'reports missing locks, install drift, updates, health, and policy failures' {
		$path = Join-Path $TestDrive 'drift.json'
		$locked = 'sha256:' + ('b' * 64)
		$script:remoteEntry = [pscustomobject]@{ digest=('sha256:' + ('c' * 64)); version='2.0.0' }
		$script:healthEntry = [pscustomobject]@{ State='scan-blocked'; Reason='CVE-TEST' }
		Mock Test-ToolchainPolicyAllowsPackage { $false,'denied for test' }
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1.0.0'; digest=$locked }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		$report = Invoke-ToolchainAudit -Path $path
		$report.HasProblems | Should -BeTrue
		$report.Summary.Updates | Should -Be 1
		$report.Summary.PolicyViolations | Should -Be 1
		$report.Summary.HealthProblems | Should -Be 1
		$report.Packages[0].LockStatus | Should -Be 'InstalledDrift'
		$report.Packages[0].Findings.Category | Should -Contain 'Update'
	}

	It 'reports missing and orphaned lock entries' {
		$path = Join-Path $TestDrive 'membership.json'
		$script:projectPackages = @('project-only:latest')
		@{ schemaVersion=1; packages=@(@{ package='lock-only'; reference='lock-only:latest'; version='1'; digest=$script:installedDigest }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		$report = Invoke-ToolchainAudit -Path $path
		($report.Packages | Where-Object Name -eq project-only).LockStatus | Should -Be 'Missing'
		($report.Packages | Where-Object Name -eq lock-only).LockStatus | Should -Be 'Orphaned'
	}

	It 'verifies signatures on request and reports verification failures' {
		$path = Join-Path $TestDrive 'signature.json'
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1'; digest=$script:installedDigest }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		(Invoke-ToolchainAudit -Path $path -VerifySignatures).Packages[0].SignatureStatus | Should -Be 'Verified'
		Mock Invoke-ToolchainVerify { throw 'bad signature' }
		$report = Invoke-ToolchainAudit -Path $path -VerifySignatures
		$report.Packages[0].SignatureStatus | Should -Be 'Failed'
		$report.Summary.SignatureFailures | Should -Be 1
	}

	It 'supports JSON and strict CI failure behavior' {
		$missing = Join-Path $TestDrive 'missing.json'
		$json = Invoke-ToolchainAudit -Path $missing -Json | ConvertFrom-Json
		$json.LockPresent | Should -BeFalse
		$json.HasProblems | Should -BeTrue
		{ Invoke-ToolchainAudit -Path $missing -Strict } | Should -Throw '*audit found*'
	}

	It 'reports remote errors and required offline signature verification' {
		$path = Join-Path $TestDrive 'offline.json'
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1'; digest=$script:installedDigest }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		Mock Get-ToolchainRemotePackageLockEntry { throw 'registry unavailable' }
		$script:signatureRequired = $true
		$script:offlineRepo = 'C:\offline'
		$report = Invoke-ToolchainAudit -Path $path
		$report.Packages[0].RemoteStatus | Should -Be 'Error'
		$report.Packages[0].SignatureStatus | Should -Be 'Offline'
		$report.Packages[0].Findings.Category | Should -Contain 'Signature'
	}

	It 'safely regenerates the lock, restores packages, and re-audits with Fix' {
		$path = Join-Path $TestDrive 'fix.json'
		$locked = 'sha256:' + ('b' * 64)
		$fixed = 'sha256:' + ('c' * 64)
		$script:remoteEntry = [pscustomobject]@{ digest=$fixed; version='2.0.0' }
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1.0.0'; digest=$locked }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		Mock Invoke-ToolchainLock {
			@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='2.0.0'; digest=$fixed }) } |
				ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path
		}
		Mock Invoke-ToolchainRestore { $script:installedDigest = $fixed }

		$report = Invoke-ToolchainAudit -Path $path -Fix -Confirm:$false
		$report.HasProblems | Should -BeFalse
		$report.Remediation.Requested | Should -BeTrue
		$report.Remediation.Applied | Should -BeTrue
		$report.Remediation.Changed | Should -BeTrue
		$report.Remediation.Actions | Should -Contain 'RegenerateLock'
		$report.Remediation.Actions | Should -Contain 'RestorePackages'
		Should -Invoke Invoke-ToolchainLock -Times 1
		Should -Invoke Invoke-ToolchainRestore -Times 1
	}

	It 'previews fixes without mutation and blocks fixes for unsafe findings' {
		Mock Invoke-ToolchainLock {}
		Mock Invoke-ToolchainRestore {}
		$missing = Join-Path $TestDrive 'preview.json'
		$preview = Invoke-ToolchainAudit -Path $missing -Fix -WhatIf
		$preview.Remediation.Requested | Should -BeTrue
		$preview.Remediation.Applied | Should -BeFalse
		$preview.Remediation.Actions | Should -Contain 'RegenerateLock'
		Should -Invoke Invoke-ToolchainLock -Times 0
		Should -Invoke Invoke-ToolchainRestore -Times 0

		$path = Join-Path $TestDrive 'blocked.json'
		@{ schemaVersion=1; packages=@(@{ package='demo'; reference='demo:latest'; version='1.0.0'; digest=$script:installedDigest }) } |
			ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
		$script:healthEntry = [pscustomobject]@{ State='blocked'; Reason='unsafe payload' }
		{ Invoke-ToolchainAudit -Path $path -Fix -Confirm:$false } | Should -Throw '*cannot safely fix*Health*'
		Should -Invoke Invoke-ToolchainLock -Times 0
		Should -Invoke Invoke-ToolchainRestore -Times 0
	}
}
