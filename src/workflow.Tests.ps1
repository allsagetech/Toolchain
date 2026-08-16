<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	$repositoryRoot = Split-Path $PSScriptRoot -Parent
	$testWorkflowPath = Join-Path $repositoryRoot '.github/workflows/test.yml'
	$testWorkflow = Get-Content -LiteralPath $testWorkflowPath -Raw
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
}
