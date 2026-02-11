<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\policy.ps1"
}

Describe 'Test-TruthyValue' {
	It 'treats common false-y values as false' {
		foreach ($v in @($null,'', '0','false','FALSE','no','off','n','f','  ')) {
			(Test-TruthyValue $v) | Should -BeFalse
		}
	}
	It 'treats other values as true' {
		foreach ($v in @('1','true','yes','on','y','t','something')) {
			(Test-TruthyValue $v) | Should -BeTrue
		}
	}
}

Describe 'Toolchain version parsing and comparisons' {
	It 'normalizes version strings' {
		(ConvertTo-ToolchainVersionString 'v1.2.3') | Should -Be '1.2.3'
		(ConvertTo-ToolchainVersionString '1.2.3_4') | Should -Be '1.2.3+4'
		(ConvertTo-ToolchainVersionString '1.2') | Should -Be '1.2'
	}

	It 'converts versions to tuples and compares them' {
		(ConvertTo-ToolchainVersionTuple '1.2.3' | ForEach-Object { $_ }) | Should -Be 1,2,3
		(ConvertTo-ToolchainVersionTuple '1.2' | ForEach-Object { $_ }) | Should -Be 1,2,0
		{ ConvertTo-ToolchainVersionTuple 'x' } | Should -Throw

		(Compare-ToolchainVersionTuple @(1,0,0) @(1,0,1)) | Should -Be (-1)
		(Compare-ToolchainVersionTuple @(2,0,0) @(1,9,9)) | Should -Be 1
		(Compare-ToolchainVersionTuple @(1,2,3) @(1,2,3)) | Should -Be 0
	}

	It 'evaluates comparators and constraints' {
		(Test-ToolchainComparator -Left '1.2.0' -Op '>=' -Right '1.2.0') | Should -BeTrue
		(Test-ToolchainComparator -Left '2.0.1' -Op '<' -Right '2.0.1') | Should -BeFalse

		(Test-ToolchainConstraintMatch -Constraint '*' -Version '1.0.0' -Tag '' -Digest '') | Should -BeTrue
		(Test-ToolchainConstraintMatch -Constraint 'latest' -Version '' -Tag 'latest' -Digest '') | Should -BeTrue
		(Test-ToolchainConstraintMatch -Constraint '1.*' -Version '1.2.3' -Tag '' -Digest '') | Should -BeTrue
		(Test-ToolchainConstraintMatch -Constraint '>=1.0.0 <2.0.1' -Version '1.5.0' -Tag '' -Digest '') | Should -BeTrue
		(Test-ToolchainConstraintMatch -Constraint '>=1.0.0 <2.0.1 nope' -Version '1.5.0' -Tag '' -Digest '') | Should -BeFalse

		$d = 'sha256:' + ('a'*64)
		(Test-ToolchainConstraintMatch -Constraint $d -Version '' -Tag '' -Digest $d) | Should -BeTrue
		(Test-ToolchainConstraintMatch -Constraint '1.2.3' -Version 'v1.2.3' -Tag '' -Digest '') | Should -BeTrue
	}
}

Describe 'Toolchain policy loading and enforcement' {
	BeforeEach {
		$script:prevPolicy = $global:ToolchainPolicy
		$script:prevPolicyPath = $global:ToolchainPolicyPath
		$script:prevEnvPolicyPath = (Get-Item env:ToolchainPolicyPath -ErrorAction SilentlyContinue).Value
		$global:ToolchainPolicy = $null
		$global:ToolchainPolicyPath = $null
		Remove-Item env:ToolchainPolicyPath -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS -ErrorAction SilentlyContinue
	}
	AfterEach {
		$global:ToolchainPolicy = $script:prevPolicy
		$global:ToolchainPolicyPath = $script:prevPolicyPath
		if ($null -eq $script:prevEnvPolicyPath) {
			Remove-Item env:ToolchainPolicyPath -ErrorAction SilentlyContinue
		} else {
			$env:ToolchainPolicyPath = $script:prevEnvPolicyPath
		}
	}

	It 'resolves policy path from global, env, or config directory' {
		$global:ToolchainPolicyPath = 'C:\p1.json'
		GetToolchainPolicyPath | Should -Be 'C:\p1.json'

		$global:ToolchainPolicyPath = $null
		$env:ToolchainPolicyPath = 'C:\p2.json'
		GetToolchainPolicyPath | Should -Be 'C:\p2.json'

		Remove-Item env:ToolchainPolicyPath -ErrorAction SilentlyContinue
		Mock FindConfig { 'C:\work\Toolchain.ps1' }
		GetToolchainPolicyPath | Should -Be 'C:\work\Toolchain.policy.json'
	}

	It 'loads policy JSON and caches it; returns null when no file' {
		Mock GetToolchainPolicyPath { $null }
		(GetToolchainPolicy) | Should -Be $null

		$tmp = Join-Path $env:TEMP ('policy-' + [Guid]::NewGuid().ToString() + '.json')
		try {
			'{"defaultAction":"allow","requireSignedManifests":true,"trustedSigners":[" aa bb " ]}' | Out-File -LiteralPath $tmp -Encoding utf8
			Mock GetToolchainPolicyPath { $tmp }
			$p1 = GetToolchainPolicy
			$p2 = GetToolchainPolicy
			$p1.requireSignedManifests | Should -BeTrue
			$p2 | Should -Be $p1
			(Get-ToolchainPolicyTrustedSigner) | Should -Be @('AABB')
		} finally {
			Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
		}
	}

	It 'throws when policy json is invalid' {
		$tmp = Join-Path $env:TEMP ('policy-' + [Guid]::NewGuid().ToString() + '.json')
		try {
			'{not json' | Out-File -LiteralPath $tmp -Encoding utf8
			Mock GetToolchainPolicyPath { $tmp }
			{ GetToolchainPolicy } | Should -Throw '*Failed to parse policy JSON*'
		} finally {
			Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
		}
	}

	It 'enforces allowed registries and repositories' {
		$policy = @{ allowedRegistries = @('example.com'); allowedRepositories = @('repo/name') }
		$ok, $reason = Test-ToolchainPolicyAllowsRegistry -Policy $policy -RegistryBaseUrl 'https://example.com' -Repository 'repo/name'
		$ok | Should -BeTrue
		$ok, $reason = Test-ToolchainPolicyAllowsRegistry -Policy $policy -RegistryBaseUrl 'https://other.com' -Repository 'repo/name'
		$ok | Should -BeFalse
		$reason | Should -Match 'registry not allowed'
		$ok, $reason = Test-ToolchainPolicyAllowsRegistry -Policy $policy -RegistryBaseUrl 'https://example.com' -Repository 'other/repo'
		$ok | Should -BeFalse
		$reason | Should -Match 'repository not allowed'
	}

	It 'enforces per-package allow/deny and defaultAction' {
		$policy = @{ defaultAction='deny'; packages = @{ foo = @{ allow = @('1.*') } } }
		$ok, $reason = Test-ToolchainPolicyAllowsPackage -Policy $policy -Package 'foo' -Version '1.2.3' -Tag '' -Digest ''
		$ok | Should -BeTrue
		$ok, $reason = Test-ToolchainPolicyAllowsPackage -Policy $policy -Package 'foo' -Version '2.0.1' -Tag '' -Digest ''
		$ok | Should -BeFalse
		$ok, $reason = Test-ToolchainPolicyAllowsPackage -Policy $policy -Package 'bar' -Version '1.0.0' -Tag '' -Digest ''
		$ok | Should -BeFalse
		$reason | Should -Match 'defaultAction=deny'

		$policy2 = @{ packages = @{ foo = @{ deny = @('latest') } } }
		$ok, $reason = Test-ToolchainPolicyAllowsPackage -Policy $policy2 -Package 'foo' -Version '' -Tag 'latest' -Digest ''
		$ok | Should -BeFalse
		$reason | Should -Match 'denied by policy'
	}

	It 'Assert-ToolchainPolicyAllowed throws with a safe package colon format' {
		Mock GetToolchainPolicy { @{ allowedRegistries=@('nope') } }
		{ Assert-ToolchainPolicyAllowed -Action 'pull' -Package 'foo' -RegistryBaseUrl 'https://example.com' -Repository 'repo' } | Should -Throw '*for foo:*'
	}

	It 'requireSignedManifests can be driven by env var' {
		Mock GetToolchainPolicy { $null }
		$env:TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS = '1'
		(Get-ToolchainPolicyRequireSignedManifest) | Should -BeTrue
	}
}

Describe 'Cosign policy helpers' {
	BeforeEach {
		Remove-Item env:TOOLCHAIN_COSIGN_VERIFY -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_COSIGN_KEY -ErrorAction SilentlyContinue
	}

	It 'reads requireCosign and cosignKey from policy' {
		Mock GetToolchainPolicy { @{ requireCosign = $true; cosignKey = 'k.pub' } }
		(Get-ToolchainPolicyRequireCosign) | Should -BeTrue
		(Get-ToolchainPolicyCosignKey) | Should -Be 'k.pub'
	}

	It 'allows env overrides' {
		$env:TOOLCHAIN_COSIGN_VERIFY = 'false'
		$env:TOOLCHAIN_COSIGN_KEY = 'env.pub'
		Mock GetToolchainPolicy { @{ requireCosign = $true; cosignKey = 'k.pub' } }
		(Get-ToolchainPolicyRequireCosign) | Should -BeFalse
		(Get-ToolchainPolicyCosignKey) | Should -Be 'env.pub'
	}
}
