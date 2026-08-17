<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function GetRegistryBaseUrl { 'https://registry.example.test' }
	function Test-TruthyValue { param($Value) return $Value -and $Value -notin @('0','false') }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Private registry credential discovery' {
	BeforeEach {
		$script:oldDockerConfig = $env:DOCKER_CONFIG
		$script:oldAuthFile = $env:TOOLCHAIN_AUTH_FILE
		$script:oldRegistryAuthFile = $env:REGISTRY_AUTH_FILE
		$script:oldUsername = $env:TOOLCHAIN_USERNAME
		$script:oldPassword = $env:TOOLCHAIN_PASSWORD
		$script:oldDisableHelpers = $env:TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS
		$env:DOCKER_CONFIG = Join-Path $TestDrive 'missing-docker-config'
		$env:TOOLCHAIN_AUTH_FILE = Join-Path $TestDrive 'missing-auth.json'
		$env:REGISTRY_AUTH_FILE = Join-Path $TestDrive 'missing-containers-auth.json'
		Remove-Item Env:TOOLCHAIN_USERNAME,Env:TOOLCHAIN_PASSWORD,Env:TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS -ErrorAction SilentlyContinue
	}

	AfterEach {
		$env:DOCKER_CONFIG = $script:oldDockerConfig
		$env:TOOLCHAIN_AUTH_FILE = $script:oldAuthFile
		$env:REGISTRY_AUTH_FILE = $script:oldRegistryAuthFile
		$env:TOOLCHAIN_USERNAME = $script:oldUsername
		$env:TOOLCHAIN_PASSWORD = $script:oldPassword
		$env:TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS = $script:oldDisableHelpers
	}

	It 'prefers paired explicit credentials and rejects incomplete pairs' {
		$env:TOOLCHAIN_USERNAME = 'alice'
		$env:TOOLCHAIN_PASSWORD = 'secret'
		$credential = Get-ToolchainRegistryCredential
		$credential.Username | Should -Be 'alice'
		$credential.Secret | Should -Be 'secret'
		$credential.Source | Should -Be 'environment'
		Remove-Item Env:TOOLCHAIN_PASSWORD
		{ Get-ToolchainRegistryCredential } | Should -Throw '*must be set together*'
	}

	It 'reads Docker auth and identity tokens without exposing them in the source' {
		$authFile = Join-Path $TestDrive 'auth.json'
		$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('bob:private-password'))
		@{ auths = @{ 'registry.example.test' = @{ auth=$encoded } } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $authFile -Encoding utf8
		$env:TOOLCHAIN_AUTH_FILE = $authFile
		$credential = Get-ToolchainRegistryCredential
		$credential.Username | Should -Be 'bob'
		$credential.Secret | Should -Be 'private-password'
		$credential.Source | Should -Be $authFile

		@{ auths = @{ 'registry.example.test' = @{ identitytoken='identity-secret' } } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $authFile -Encoding utf8
		$credential = Get-ToolchainRegistryCredential
		$credential.IdentityToken | Should -Be 'identity-secret'
	}

	It 'uses configured credential helpers and supports an explicit helper opt-out' {
		$authFile = Join-Path $TestDrive 'helper.json'
		@{ auths=@{}; credHelpers=@{ 'registry.example.test'='test-helper' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $authFile -Encoding utf8
		$env:TOOLCHAIN_AUTH_FILE = $authFile
		Mock Invoke-ToolchainCredentialHelper { [pscustomobject]@{ Username='helper-user'; Secret='helper-secret'; Source='helper:test-helper' } }
		(Get-ToolchainRegistryCredential).Source | Should -Be 'helper:test-helper'
		Should -Invoke Invoke-ToolchainCredentialHelper -Times 1 -Exactly -ParameterFilter { $Helper -eq 'test-helper' }

		$env:TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS = '1'
		Get-ToolchainRegistryCredential | Should -BeNullOrEmpty
		Should -Invoke Invoke-ToolchainCredentialHelper -Times 1 -Exactly
	}

	It 'continues without credentials when a configured helper is unavailable' {
		$authFile = Join-Path $TestDrive 'unavailable-helper.json'
		@{ auths=@{}; credsStore='unavailable' } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $authFile -Encoding utf8
		$env:TOOLCHAIN_AUTH_FILE = $authFile
		Mock Invoke-ToolchainCredentialHelper { throw 'credential helper unavailable' }

		Get-ToolchainRegistryCredential | Should -BeNullOrEmpty
		Should -Invoke Invoke-ToolchainCredentialHelper -Times 1 -Exactly
	}
}
