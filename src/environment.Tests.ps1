<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	$script:testEnvironment = @{}
	function Get-ToolchainEnvironmentItems {
		foreach ($key in $script:testEnvironment.Keys) { [pscustomobject]@{ Name=$key; Value=$script:testEnvironment[$key] } }
	}
	function Set-ToolchainEnvironmentValue {
		param($Name, $Value)
		if ($null -eq $Value) { $null = $script:testEnvironment.Remove($Name) } else { $script:testEnvironment[$Name] = [string]$Value }
	}
	function GetRegistryBaseUrl { 'https://registry.example.test' }
	function GetRegistryRepoName { 'owner/toolchains' }
	function GetRegistryPlatformOs { 'linux' }
	function GetRegistryPlatformArch { 'amd64' }
	function Read-ToolchainProject { }
	function Get-ToolchainLockPath { }
	function Read-ToolchainLock { }
	function Invoke-ToolchainLock { param($Packages, $Path, $ProjectDigest) }
	function Invoke-ToolchainRestore { }
	function Resolve-ToolchainProjectPackages { }
	function Invoke-ToolchainLoad { }
	function Write-ToolchainInfo { }
	function AsPackage { param([Parameter(ValueFromPipeline)]$Reference) process { @{ Package = ([string]$Reference -split '[:@]')[0] } } }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain sync' {
	BeforeEach {
		$script:ToolchainActivation = $null
		$script:project = [pscustomobject]@{
			Path = Join-Path $TestDrive 'toolchain.yaml'
			Digest = 'sha256:' + ('a' * 64)
			PackageNames = @('node')
			PackageSpecs = @(@{ Name='node'; Constraint='^24'; Configuration='default'; Dependencies=@() })
			Packages = @()
		}
		$script:lockPath = Join-Path $TestDrive 'Toolchain.lock.json'
		Set-Content -LiteralPath $script:lockPath -Value '{}' -Encoding utf8
		$script:lock = [pscustomobject]@{
			projectDigest = $script:project.Digest
			registry = 'https://registry.example.test'
			repository = 'owner/toolchains'
			packages = @([pscustomobject]@{ package='node'; digest=('sha256:' + ('b' * 64)); configuration='default'; platform='linux/amd64' })
		}
		Mock Read-ToolchainProject { $script:project }
		Mock Get-ToolchainLockPath { $script:lockPath }
		Mock Read-ToolchainLock { $script:lock }
		Mock Invoke-ToolchainRestore { }
		Mock Invoke-ToolchainLock { $script:lock }
		Mock Resolve-ToolchainProjectPackages { @('node:24.2.0::default') }
		Mock Write-ToolchainInfo { }
	}

	It 'reuses a coherent lock and restores it without resolving the catalog' {
		$result = Invoke-ToolchainSync -PassThru
		$result.UsedExistingLock | Should -BeTrue
		$result.Packages | Should -Be 1
		Should -Invoke Resolve-ToolchainProjectPackages -Times 0 -Exactly
		Should -Invoke Invoke-ToolchainRestore -Times 1 -Exactly
	}

	It 'refreshes stale locks, supports frozen mode, and records the project digest' {
		$script:lock.projectDigest = 'sha256:' + ('c' * 64)
		$result = Invoke-ToolchainSync -PassThru -NoRestore
		$result.UsedExistingLock | Should -BeFalse
		Should -Invoke Resolve-ToolchainProjectPackages -Times 1 -Exactly
		Should -Invoke Invoke-ToolchainLock -Times 1 -Exactly -ParameterFilter { $ProjectDigest -eq $script:project.Digest }
		Should -Invoke Invoke-ToolchainRestore -Times 0 -Exactly
		{ Invoke-ToolchainSync -Frozen } | Should -Throw '*missing or stale*'
	}
}

Describe 'Toolchain activation lifecycle' {
	BeforeEach {
		$script:ToolchainActivation = $null
		$script:testEnvironment = @{ PATH='/usr/bin'; EXISTING='before' }
		$project = [pscustomobject]@{
			Path = '/work/toolchain.yaml'
			PackageSpecs = @(@{ Name='node'; Constraint='24'; Configuration='default'; Dependencies=@() })
		}
		Mock Read-ToolchainProject { $project }
		Mock Resolve-ToolchainProjectPackages { @('node:24.2.0::default') }
		Mock Invoke-ToolchainLoad {
			$script:testEnvironment.PATH = '/toolchain/node/bin:/usr/bin'
			$script:testEnvironment.NODE_HOME = '/toolchain/node'
		}
		Mock Write-ToolchainInfo { }
	}

	It 'records changed values, is idempotent, and restores the original environment' {
		$activation = Invoke-ToolchainActivate -NoSync -PassThru
		$activation.Packages | Should -Be @('node:24.2.0::default')
		$script:testEnvironment.PATH | Should -Be '/toolchain/node/bin:/usr/bin'
		$script:testEnvironment.TOOLCHAIN_ACTIVE_PROJECT | Should -Be '/work/toolchain.yaml'
		$again = Invoke-ToolchainActivate -NoSync -PassThru
		$again.ActivatedAt | Should -Be $activation.ActivatedAt
		Should -Invoke Invoke-ToolchainLoad -Times 1 -Exactly

		$removed = Invoke-ToolchainDeactivate -PassThru
		$removed.Project | Should -Be '/work/toolchain.yaml'
		$script:testEnvironment.PATH | Should -Be '/usr/bin'
		$script:testEnvironment.EXISTING | Should -Be 'before'
		$script:testEnvironment.ContainsKey('NODE_HOME') | Should -BeFalse
		$script:testEnvironment.ContainsKey('TOOLCHAIN_ACTIVE_PROJECT') | Should -BeFalse
	}
}
