<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	$repositoryRoot = Split-Path $PSScriptRoot -Parent
	$testWorkflowPath = Join-Path $repositoryRoot '.github/workflows/test.yml'
	$testWorkflow = Get-Content -LiteralPath $testWorkflowPath -Raw
	$releaseWorkflowPath = Join-Path $repositoryRoot '.github/workflows/release.yml'
	$releaseWorkflow = Get-Content -LiteralPath $releaseWorkflowPath -Raw
}

Describe 'GitHub Actions test workflow' {
	It 'authenticates Codecov uploads with GitHub OIDC' {
		$testWorkflow | Should -Match '(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*$'
		$testWorkflow | Should -Match '(?ms)^\s{2}test:\s*\r?\n.*?^\s{4}permissions:\s*\r?\n\s{6}contents:\s*read\s*\r?\n\s{6}id-token:\s*write\s*$'
		$testWorkflow | Should -Match '(?ms)- name:\s*Upload coverage to Codecov.*?with:.*?use_oidc:\s*true'
		$testWorkflow | Should -Not -Match 'secrets\.CODECOV_TOKEN'
		$testWorkflow | Should -Not -Match '(?ms)^\s{2}registry-integration:.*?^\s{4}permissions:.*?id-token:\s*write'
	}

	It 'does not fail CI when an unconfigured Codecov repository rejects an upload' {
		$testWorkflow | Should -Match '(?ms)- name:\s*Upload coverage to Codecov.*?with:.*?fail_ci_if_error:\s*false'
	}

	It 'tests the OCI client against an authenticated registry' {
		$testWorkflow | Should -Match 'REGISTRY_AUTH=htpasswd'
		$testWorkflow | Should -Match 'TOOLCHAIN_USERNAME:\s*integration'
		$testWorkflow | Should -Match 'TOOLCHAIN_PASSWORD:\s*integration-password'
		$testWorkflow | Should -Match 'Anonymous registry access was not denied'
		$testWorkflow | Should -Match 'docker login localhost:5000'
	}

	It 'retains CI logs for the documented bounded period' {
		$testWorkflow | Should -Match '(?ms)uses:\s*actions/upload-artifact@.*?retention-days:\s*14'
	}

	It 'gates the cross-platform client on Linux and macOS' {
		$testWorkflow | Should -Match 'os:\s*macos-15'
		$testWorkflow | Should -Match "runner\.os == 'Linux' \|\| runner\.os == 'macOS'"
		$testWorkflow | Should -Match 'project\.Tests\.ps1'
		$releaseWorkflow | Should -Match 'os:\s*macos-15'
	}

	It 'publishes complete drafts and fails unless GitHub locks the release' {
		$releaseWorkflow | Should -Match '(?ms)gh release create.*?--draft.*?gh release edit.*?--draft=false'
		$releaseWorkflow | Should -Match 'gh release view .*--json isImmutable'
		$releaseWorkflow | Should -Match 'gh release delete .*--yes'
		$releaseWorkflow | Should -Match 'Release immutability is not enforced'
	}

	It 'tests and publishes a signed multi-architecture Toolchain agent' {
		$testWorkflow | Should -Match '(?ms)^\s{2}agent:.*?go test \./\.\.\..*?docker build --tag toolchain-agent:test'
		$releaseWorkflow | Should -Match 'platforms:\s*linux/amd64,linux/arm64'
		$releaseWorkflow | Should -Match 'ghcr\.io/allsagetech/toolchain-agent:\$tagVersion'
		$releaseWorkflow | Should -Match 'cosign sign --yes'
		$releaseWorkflow | Should -Match 'packages:\s*write'
		$releaseWorkflow | Should -Match 'Immutable agent tag already exists'
	}

	It 'smoke-tests the built package surface before publishing' {
		$releaseWorkflow | Should -Match 'Run built package creation smoke test'
		$releaseWorkflow | Should -Match "Invoke-Toolchain -Command package -ArgumentList"
		$releaseWorkflow | Should -Match "Invoke-Toolchain -Command help -ArgumentList @\('cluster', 'doctor'\)"
	}
}
