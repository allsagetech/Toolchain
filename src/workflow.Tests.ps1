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
		$testWorkflow | Should -Match '(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*\r?\n\s+id-token:\s*write\s*$'
		$testWorkflow | Should -Match '(?ms)- name:\s*Upload coverage to Codecov.*?with:.*?use_oidc:\s*true'
		$testWorkflow | Should -Not -Match 'secrets\.CODECOV_TOKEN'
	}
}
