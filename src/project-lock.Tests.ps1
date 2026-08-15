<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function FindConfig {}
	function GetConfigPackages {}
	function GetRegistryBaseUrl { 'https://registry.example.test/v2' }
	function GetRegistryRepoName { 'owner/toolchains' }
	function GetRegistryPlatformOs { 'windows' }
	function GetRegistryPlatformArch { 'amd64' }
	function AsPackage {
		param([Parameter(ValueFromPipeline)]$Ref)
		process { [pscustomobject]@{ Package=[string]$Ref; Version='latest'; Config='default'; Tag='latest' } }
	}
	function AsTagString { param([Parameter(ValueFromPipeline)]$Tag) process { [string]$Tag } }
	function Assert-ToolchainPolicyAllowed { param($Package,$Tag,$Action) }
	function ResolveDockerRef { param($Pkg) "owner/toolchains:$($Pkg.Package)-latest" }
	function GetResolvedManifestResponse { param($Ref,$Method) }
	function GetVerifiedManifestResponse { param($Ref) }
	function GetDigest { param([Parameter(ValueFromPipeline)]$Resp) process { [string]$Resp.TestDigest } }
	function GetJsonResponse { param([Parameter(ValueFromPipeline)]$Resp) process { $Resp.TestManifest } }
	function TryEachPackage { param($Packages,$ScriptBlock,$ActionDescription) }
	function Invoke-PullPackageWithRetry { param($PackageRef) }
	function Invoke-ToolchainCosignVerify { param($RepoDigestRef,[switch]$Force) }
	function Write-ToolchainInfo { param($Message) }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')

	function New-TestManifestResponse {
		param([string]$Digest, $Manifest = ([pscustomobject]@{}))
		$response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$response | Add-Member -NotePropertyName TestDigest -NotePropertyValue $Digest
		$response | Add-Member -NotePropertyName TestManifest -NotePropertyValue $Manifest
		return $response
	}
}

Describe 'Toolchain project lock paths and entries' {
	It 'resolves explicit, project, and current-directory lock paths' {
		$explicit = Join-Path $TestDrive 'custom.lock.json'
		Get-ToolchainLockPath -Path $explicit | Should -Be ([IO.Path]::GetFullPath($explicit))
		Mock FindConfig { Join-Path $TestDrive 'project\Toolchain.ps1' }
		Get-ToolchainLockPath | Should -Be (Join-Path $TestDrive 'project\Toolchain.lock.json')
		Mock FindConfig { $null }
		Get-ToolchainLockPath | Should -Be (Join-Path (Get-Location).Path 'Toolchain.lock.json')
	}

	It 'resolves a platform-specific remote digest under policy' {
		$digest = 'sha256:' + ('a' * 64)
		Mock AsPackage { [pscustomobject]@{ Package='node'; Version='22.1.0'; Config='default'; Tag='22.1.0' } }
		Mock Assert-ToolchainPolicyAllowed {}
		Mock GetResolvedManifestResponse { New-TestManifestResponse -Digest $digest }
		$entry = Get-ToolchainRemotePackageLockEntry -Reference 'node:22.1.0'
		$entry.package | Should -Be 'node'
		$entry.digest | Should -Be $digest
		$entry.platform | Should -Be 'windows/amd64'
		Should -Invoke Assert-ToolchainPolicyAllowed -Times 1 -ParameterFilter { $Action -eq 'lock' }
	}

	It 'rejects a registry response without a digest' {
		Mock GetResolvedManifestResponse { New-TestManifestResponse -Digest '' }
		{ Get-ToolchainRemotePackageLockEntry -Reference node } | Should -Throw '*did not return a digest*'
	}
}

Describe 'Toolchain project lock lifecycle' {
	BeforeEach {
		Mock GetConfigPackages { @('node','git') }
		Mock Get-ToolchainRemotePackageLockEntry {
			param($Reference)
			[ordered]@{ package=$Reference; reference=$Reference; version='1.0.0'; digest=('sha256:' + ('a' * 64)); configuration='default'; platform='windows/amd64' }
		}
		Mock Write-ToolchainInfo {}
	}

	It 'writes and atomically replaces a schema-versioned lock file' {
		$path = Join-Path $TestDrive 'nested\Toolchain.lock.json'
		$first = Invoke-ToolchainLock -Path $path
		$first.schemaVersion | Should -Be 1
		$first.packages.package | Should -Be @('node','git')
		(Test-Path -LiteralPath $path -PathType Leaf) | Should -BeTrue
		(Invoke-ToolchainLock -Packages @('node') -Path $path).packages.Count | Should -Be 1
		(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).packages.package | Should -Be 'node'
		@(Get-ChildItem -LiteralPath (Split-Path -Parent $path) -Filter '*.tmp').Count | Should -Be 0
	}

	It 'preserves packages outside a selective update' {
		$path = Join-Path $TestDrive 'Toolchain.lock.json'
		$old = @{ schemaVersion=1; packages=@(
			@{ package='node'; digest=('sha256:' + ('b' * 64)) },
			@{ package='git'; digest=('sha256:' + ('c' * 64)) }
		) } | ConvertTo-Json -Depth 5
		[IO.File]::WriteAllText($path, $old)
		$result = Invoke-ToolchainLock -Path $path -Update node
		($result.packages | Where-Object package -eq git).digest | Should -Be ('sha256:' + ('c' * 64))
		Should -Invoke Get-ToolchainRemotePackageLockEntry -Times 1 -ParameterFilter { $Reference -eq 'node' }
	}

	It 'requires a package source' {
		Mock GetConfigPackages { $null }
		{ Invoke-ToolchainLock -Path (Join-Path $TestDrive 'none.json') } | Should -Throw '*no packages provided*'
	}

	It 'validates lock documents and entries' {
		$missing = Join-Path $TestDrive 'missing.json'
		{ Read-ToolchainLock -Path $missing } | Should -Throw '*not found*'
		$path = Join-Path $TestDrive 'bad.json'
		[IO.File]::WriteAllText($path, '{"schemaVersion":2,"packages":[]}')
		{ Read-ToolchainLock -Path $path } | Should -Throw '*invalid Toolchain lock file*'
		[IO.File]::WriteAllText($path, '{"schemaVersion":1,"packages":[{"package":"../bad","digest":"nope"}]}')
		{ Read-ToolchainLock -Path $path } | Should -Throw '*invalid package entry*'
	}

	It 'restores exact package digests and configurations' {
		$path = Join-Path $TestDrive 'restore.json'
		$doc = @{ schemaVersion=1; packages=@(
			@{ package='node'; digest=('sha256:' + ('d' * 64)); configuration='debug' },
			@{ package='git'; digest=('sha256:' + ('e' * 64)) }
		) } | ConvertTo-Json -Depth 5
		[IO.File]::WriteAllText($path, $doc)
		$script:restoredRefs = @()
		Mock TryEachPackage {
			param($Packages,$ScriptBlock,$ActionDescription)
			$script:restoredRefs = @($Packages)
			foreach ($package in $Packages) { $package | & $ScriptBlock }
		}
		Mock Invoke-PullPackageWithRetry {}
		Invoke-ToolchainRestore -Path $path
		$script:restoredRefs | Should -Be @(
			('node@sha256:' + ('d' * 64) + '::debug'),
			('git@sha256:' + ('e' * 64) + '::default')
		)
		Should -Invoke Invoke-PullPackageWithRetry -Times 2
	}
}

Describe 'Toolchain explicit signature verification' {
	It 'verifies both an index and its selected platform manifest' {
		$indexDigest = 'sha256:' + ('1' * 64)
		$leafDigest = 'sha256:' + ('2' * 64)
		Mock GetConfigPackages { @('kubectl') }
		Mock AsPackage { [pscustomobject]@{ Package='kubectl'; Version='1.34.0'; Config='default'; Tag='1.34.0' } }
		Mock GetVerifiedManifestResponse { New-TestManifestResponse -Digest $indexDigest -Manifest ([pscustomobject]@{ manifests=@([pscustomobject]@{}) }) }
		Mock GetResolvedManifestResponse { New-TestManifestResponse -Digest $leafDigest }
		Mock Invoke-ToolchainCosignVerify {}
		$result = Invoke-ToolchainVerify
		$result.Verified | Should -BeTrue
		$result.IndexDigest | Should -Be $indexDigest
		$result.Digest | Should -Be $leafDigest
		Should -Invoke Invoke-ToolchainCosignVerify -Times 2 -ParameterFilter { $Force }
	}

	It 'verifies a single manifest once and supports JSON output' {
		$digest = 'sha256:' + ('3' * 64)
		Mock AsPackage { [pscustomobject]@{ Package='node'; Version='22'; Config='default'; Tag='22' } }
		Mock GetVerifiedManifestResponse { New-TestManifestResponse -Digest $digest }
		Mock GetResolvedManifestResponse { New-TestManifestResponse -Digest $digest }
		Mock Invoke-ToolchainCosignVerify {}
		$result = Invoke-ToolchainVerify -Packages node -Json | ConvertFrom-Json
		$result.Verified | Should -BeTrue
		$result.IndexDigest | Should -BeNullOrEmpty
		Should -Invoke Invoke-ToolchainCosignVerify -Times 1
	}

	It 'requires packages when no project configuration exists' {
		Mock GetConfigPackages { $null }
		{ Invoke-ToolchainVerify } | Should -Throw '*no packages provided*'
	}
}
