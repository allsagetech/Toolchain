<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSScriptRoot\config.ps1
	. $PSScriptRoot\definition.ps1
	$script:specRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'schema'
	$script:specManifest = Get-Content -LiteralPath (Join-Path $script:specRoot 'package-spec.manifest.json') -Raw | ConvertFrom-Json
}

Describe 'Toolchain package specification corpus' {
	It 'uses the declared package specification version' {
		$version = (Get-Content -LiteralPath (Join-Path $script:specRoot 'PACKAGE_SPEC_VERSION') -Raw).Trim()
		$version | Should -Be ([string]$script:specManifest.version)
	}

	It 'accepts valid fixture <fixture>' -ForEach @(
		@{ fixture = 'fixtures/valid/minimal.json' }
		@{ fixture = 'fixtures/valid/configurations.json' }
	) {
		$path = Join-Path $script:specRoot $fixture
		$definition = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json | ConvertTo-HashTable
		{ Assert-ToolchainDefinition -Definition $definition -Context $fixture } | Should -Not -Throw
	}

	It 'rejects invalid fixture <fixture>' -ForEach @(
		@{ fixture = 'fixtures/invalid/missing-env.json' }
		@{ fixture = 'fixtures/invalid/blank-env-name.json' }
		@{ fixture = 'fixtures/invalid/non-string-value.json' }
		@{ fixture = 'fixtures/invalid/config-missing-env.json' }
	) {
		$path = Join-Path $script:specRoot $fixture
		$definition = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json | ConvertTo-HashTable
		{ Assert-ToolchainDefinition -Definition $definition -Context $fixture } | Should -Throw
	}
}
